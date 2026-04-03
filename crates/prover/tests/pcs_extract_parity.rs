use anyhow::{Result, ensure};
use binius_field::{BinaryField128bGhash, Field, PackedBinaryGhash1x128b};
use binius_hash::{ParallelCompressionAdaptor, StdCompression, StdDigest};
use binius_iop::{
	basefold as verifier_basefold,
	basefold_compiler::BaseFoldVerifierCompiler,
	basefold_extract::{
		self, ExtractFriParams, ExtractMerkleLayer, ExtractMerkleOpening, ExtractMerkleVector,
	},
	channel::OracleSpec,
	fri::{self, MinProofSizeStrategy},
	merkle_tree::BinaryMerkleTreeScheme,
};
use binius_iop_prover::{
	basefold_compiler::BaseFoldProverCompiler, channel::IOPProverChannel,
	merkle_tree::prover::BinaryMerkleTreeProver,
};
use binius_math::{
	BinarySubspace,
	multilinear::{eq::eq_ind_partial_eval, evaluate::evaluate},
	ntt::{DomainContext, NeighborsLastSingleThread, domain_context::GenericOnTheFly},
	test_utils::{random_field_buffer, random_scalars},
};
use binius_prover::ring_switch as prover_ring_switch;
use binius_transcript::{
	Buf, ProverTranscript, TranscriptReader, VerifierTranscript,
	fiat_shamir::{CanSample, CanSampleBits, HasherChallenger},
};
use binius_verifier::{pcs_extract, ring_switch as verifier_ring_switch, ring_switch_extract};
use digest::Output;
use rand::{SeedableRng, rngs::StdRng};
use std::{hint::black_box, time::Instant};

type F = BinaryField128bGhash;
type P = PackedBinaryGhash1x128b;
type MerkleScheme = BinaryMerkleTreeScheme<F, StdDigest, StdCompression>;
type MerkleDigest = Output<StdDigest>;
type StdChallenger = HasherChallenger<StdDigest>;

const LOG_PACKING: usize = 7;
const PACKING_DEGREE: usize = 1 << LOG_PACKING;
const LOG_INV_RATE: usize = 1;
const SECURITY_BITS: usize = 32;

#[derive(Clone)]
struct BenchCase {
	evaluation_claim: F,
	eval_point: Vec<F>,
	fri_params: fri::FRIParams<F>,
	merkle_scheme: MerkleScheme,
	proof_bytes: Vec<u8>,
	extract_statement: pcs_extract::ExtractPcsStatement,
	extract_transcript: pcs_extract::ExtractPcsTranscriptView,
}

fn digest_to_extract(digest: impl AsRef<[u8]>) -> [u8; 32] {
	digest
		.as_ref()
		.try_into()
		.expect("SHA-256 digests are 32 bytes")
}

fn calculate_commit_rounds(
	log_batch_size: usize,
	fold_arities: &[usize],
	n_rounds: usize,
) -> Vec<bool> {
	let mut result = vec![false; n_rounds];
	let mut round_idx = log_batch_size;
	if round_idx < n_rounds {
		result[round_idx] = true;
	}
	for &arity in fold_arities {
		round_idx += arity;
		if round_idx < n_rounds {
			result[round_idx] = true;
		}
	}
	result
}

fn extract_fri_params(
	fri_params: &fri::FRIParams<F>,
	merkle_scheme: &MerkleScheme,
) -> ExtractFriParams {
	let domain_context = GenericOnTheFly::generate_from_subspace(fri_params.rs_code().subspace());
	let log_domain_size = domain_context.log_domain_size();
	let twiddle_evals = (1..=log_domain_size)
		.rev()
		.map(|dim| domain_context.subspace(dim).basis().to_vec())
		.collect();

	ExtractFriParams {
		log_msg_len: fri_params.log_msg_len(),
		log_batch_size: fri_params.log_batch_size(),
		fold_arities: fri_params.fold_arities().to_vec(),
		index_bits: fri_params.index_bits(),
		log_inv_rate: fri_params.rs_code().log_inv_rate(),
		n_final_challenges: fri_params.n_final_challenges(),
		n_test_queries: fri_params.n_test_queries(),
		layer_depths: fri::vcs_optimal_layers_depths_iter(fri_params, merkle_scheme).collect(),
		twiddle_evals,
	}
}

fn skip_vector_auth<B: Buf>(
	merkle_scheme: &MerkleScheme,
	advice: &mut TranscriptReader<B>,
	n_chunks: usize,
) -> Result<()> {
	for _ in 0..n_chunks {
		let _: Vec<F> = advice.read_vec(merkle_scheme.salt_len())?;
	}
	Ok(())
}

fn skip_opening_auth<B: Buf>(
	merkle_scheme: &MerkleScheme,
	advice: &mut TranscriptReader<B>,
	tree_depth: usize,
	layer_depth: usize,
) -> Result<()> {
	let _: Vec<F> = advice.read_vec(merkle_scheme.salt_len())?;
	let _: Vec<MerkleDigest> = advice.read_vec(tree_depth - layer_depth)?;
	Ok(())
}

fn extract_basefold_oracle(
	fri_params: &fri::FRIParams<F>,
	merkle_scheme: &MerkleScheme,
	codeword_commitment: [u8; 32],
	transcript: &mut VerifierTranscript<StdChallenger>,
) -> Result<basefold_extract::ExtractBasefoldTranscriptView> {
	let mut oracle = basefold_extract::ExtractProofOracle::default();
	let commit_rounds = calculate_commit_rounds(
		fri_params.log_batch_size(),
		fri_params.fold_arities(),
		fri_params.n_fold_rounds() + 1,
	);

	for round in 0..fri_params.log_msg_len() {
		let coeffs = transcript.message().read_scalar_slice::<F>(2)?;
		oracle.round_coeffs.push([coeffs[0], coeffs[1]]);
		if commit_rounds[round] {
			let commitment: MerkleDigest = transcript.message().read()?;
			oracle.commitments.push(digest_to_extract(commitment));
		}
		oracle.challenges.push(transcript.sample());
	}

	if commit_rounds[fri_params.log_msg_len()] {
		let commitment: MerkleDigest = transcript.message().read()?;
		oracle.commitments.push(digest_to_extract(commitment));
	}

	let layer_depths: Vec<_> =
		fri::vcs_optimal_layers_depths_iter(fri_params, merkle_scheme).collect();
	let terminate_codeword_len =
		1 << (fri_params.n_final_challenges() + fri_params.rs_code().log_inv_rate());

	{
		let mut advice = transcript.decommitment();
		let terminate_codeword = advice.read_scalar_slice::<F>(terminate_codeword_len)?;
		skip_vector_auth(
			merkle_scheme,
			&mut advice,
			terminate_codeword.len() >> fri_params.n_final_challenges(),
		)?;
		let terminal_root = *oracle
			.commitments
			.last()
			.expect("BaseFold always ends with a terminal commitment");
		oracle.decommitment_scalars.push(terminate_codeword.clone());
		oracle.merkle_vectors.push(ExtractMerkleVector {
			root: terminal_root,
			data: terminate_codeword,
			batch_size: 1 << fri_params.n_final_challenges(),
		});

		for (layer_idx, layer_depth) in layer_depths.iter().copied().enumerate() {
			let layer: Vec<MerkleDigest> = advice.read_vec(1 << layer_depth)?;
			let layer_digests = layer.into_iter().map(digest_to_extract).collect::<Vec<_>>();
			let root = if layer_idx == 0 {
				codeword_commitment
			} else {
				oracle.commitments[layer_idx - 1]
			};
			oracle.decommitments.push(layer_digests.clone());
			oracle.merkle_layers.push(ExtractMerkleLayer {
				root,
				layer_depth,
				layer_digests,
			});
		}
	}

	let first_layer_depth = layer_depths[0];
	for _ in 0..fri_params.n_test_queries() {
		let mut index = transcript.sample_bits(fri_params.index_bits()) as usize;
		oracle.query_indices.push(index);

		{
			let mut advice = transcript.decommitment();
			let values = advice.read_scalar_slice::<F>(1 << fri_params.log_batch_size())?;
			skip_opening_auth(
				merkle_scheme,
				&mut advice,
				fri_params.index_bits(),
				first_layer_depth,
			)?;
			oracle.decommitment_scalars.push(values.clone());
			oracle.merkle_openings.push(ExtractMerkleOpening {
				index,
				values,
				layer_depth: first_layer_depth,
				tree_depth: fri_params.index_bits(),
				layer_digests: oracle.decommitments[0].clone(),
			});
		}

		let mut log_n_cosets = fri_params.index_bits();
		for (round_idx, &arity) in fri_params.fold_arities().iter().enumerate() {
			let coset_index = index >> arity;
			log_n_cosets -= arity;
			let layer_depth = layer_depths[round_idx + 1];

			{
				let mut advice = transcript.decommitment();
				let values = advice.read_scalar_slice::<F>(1 << arity)?;
				skip_opening_auth(merkle_scheme, &mut advice, log_n_cosets, layer_depth)?;
				oracle.decommitment_scalars.push(values.clone());
				oracle.merkle_openings.push(ExtractMerkleOpening {
					index: coset_index,
					values,
					layer_depth,
					tree_depth: log_n_cosets,
					layer_digests: oracle.decommitments[round_idx + 1].clone(),
				});
			}

			index = coset_index;
		}
	}

	Ok(basefold_extract::ExtractBasefoldTranscriptView {
		proof: basefold_extract::ExtractBasefoldProofView {
			round_coeffs: oracle.round_coeffs,
			commitments: oracle.commitments,
			decommitment_scalars: oracle.decommitment_scalars,
			decommitments: oracle.decommitments,
			merkle_vectors: oracle.merkle_vectors,
			merkle_openings: oracle.merkle_openings,
			merkle_layers: oracle.merkle_layers,
		},
		sampling: basefold_extract::ExtractBasefoldSamplingView {
			challenges: oracle.challenges,
			query_indices: oracle.query_indices,
		},
	})
}

fn extract_scripted_inputs(
	fri_params: &fri::FRIParams<F>,
	merkle_scheme: &MerkleScheme,
	proof_bytes: Vec<u8>,
) -> Result<(
	[u8; 32],
	ring_switch_extract::ExtractRingSwitchTranscriptView,
	basefold_extract::ExtractBasefoldTranscriptView,
)> {
	let mut transcript = VerifierTranscript::new(StdChallenger::default(), proof_bytes);
	let codeword_commitment: MerkleDigest = transcript.message().read()?;
	let ring_switch_messages = transcript
		.message()
		.read_scalar_slice::<F>(PACKING_DEGREE)?;
	let ring_switch_challenges = (0..LOG_PACKING)
		.map(|_| transcript.sample())
		.collect::<Vec<_>>();
	let codeword_commitment = digest_to_extract(codeword_commitment);
	let basefold_oracle =
		extract_basefold_oracle(fri_params, merkle_scheme, codeword_commitment, &mut transcript)?;

	Ok((
		codeword_commitment,
		ring_switch_extract::ExtractRingSwitchTranscriptView {
			proof: ring_switch_extract::ExtractRingSwitchProofView {
				messages: ring_switch_messages,
			},
			sampling: ring_switch_extract::ExtractRingSwitchSamplingView {
				challenges: ring_switch_challenges,
			},
		},
		basefold_oracle,
	))
}

fn make_bench_case() -> Result<BenchCase> {
	let mut rng = StdRng::seed_from_u64(0);
	let n_vars = 8;
	let packed_witness = random_field_buffer::<P>(&mut rng, n_vars);
	let eval_point = random_scalars::<F>(&mut rng, n_vars + LOG_PACKING);

	let suffix_tensor = eq_ind_partial_eval::<P>(&eval_point[LOG_PACKING..]);
	let s_hat_v = prover_ring_switch::fold_1b_rows_for_b128(&packed_witness, &suffix_tensor);
	let evaluation_claim = evaluate(&s_hat_v, &eval_point[..LOG_PACKING]);

	let oracle_specs = vec![OracleSpec {
		log_msg_len: n_vars,
	}];
	let max_codeword_log_len = n_vars + LOG_INV_RATE;
	let n_test_queries = fri::calculate_n_test_queries(SECURITY_BITS, LOG_INV_RATE);
	let subspace = BinarySubspace::with_dim(max_codeword_log_len);
	let domain_context = GenericOnTheFly::generate_from_subspace(&subspace);
	let ntt = NeighborsLastSingleThread::new(domain_context);
	let merkle_prover = BinaryMerkleTreeProver::<F, StdDigest, _>::new(
		ParallelCompressionAdaptor::new(StdCompression::default()),
	);
	let verifier_compiler = BaseFoldVerifierCompiler::new(
		&ntt,
		merkle_prover.scheme().clone(),
		oracle_specs,
		LOG_INV_RATE,
		n_test_queries,
		&MinProofSizeStrategy,
	);
	let prover_compiler = BaseFoldProverCompiler::<P, _, _>::from_verifier_compiler(
		&verifier_compiler,
		ntt,
		merkle_prover,
	);

	let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
	let mut prover_channel = prover_compiler.create_channel(&mut prover_transcript);
	let oracle = prover_channel.send_oracle(packed_witness.to_ref());
	let prover_ring_switch_output =
		prover_ring_switch::prove(&packed_witness, &eval_point, &mut prover_channel);
	let expected_sumcheck_claim = prover_ring_switch_output.sumcheck_claim;
	prover_channel.prove_oracle_relations([(
		oracle,
		prover_ring_switch_output.rs_eq_ind,
		prover_ring_switch_output.sumcheck_claim,
	)]);
	let proof_bytes = prover_transcript.finalize();

	let fri_params = &verifier_compiler.fri_params()[0];
	let merkle_scheme = verifier_compiler.merkle_scheme();

	let mut live_transcript =
		VerifierTranscript::new(StdChallenger::default(), proof_bytes.clone());
	let codeword_commitment: MerkleDigest = live_transcript.message().read()?;
	let live_ring_switch =
		verifier_ring_switch::verify(evaluation_claim, &eval_point, &mut live_transcript)?;
	let live_basefold = verifier_basefold::verify(
		fri_params,
		merkle_scheme,
		codeword_commitment,
		live_ring_switch.sumcheck_claim,
		&mut live_transcript,
	)?;
	let live_opened = live_basefold.opened_linear_relation();
	let live_transparent_eval = live_ring_switch.relation.eval(&live_opened.query_point);
	ensure!(live_ring_switch.sumcheck_claim == expected_sumcheck_claim);
	ensure!(live_opened.consistency_error(live_transparent_eval) == F::ZERO);

	let extract_params = extract_fri_params(fri_params, merkle_scheme);
	let (extract_commitment, ring_switch_transcript, basefold_transcript) =
		extract_scripted_inputs(fri_params, merkle_scheme, proof_bytes.clone())?;
	let extract_statement = pcs_extract::ExtractPcsStatement {
		params: extract_params,
		codeword_commitment: extract_commitment,
		witness_eval: evaluation_claim,
		eval_point: eval_point.clone(),
	};
	let extract_transcript = pcs_extract::ExtractPcsTranscriptView {
		ring_switch: ring_switch_transcript,
		basefold: basefold_transcript,
	};

	Ok(BenchCase {
		evaluation_claim,
		eval_point,
		fri_params: fri_params.clone(),
		merkle_scheme: merkle_scheme.clone(),
		proof_bytes,
		extract_statement,
		extract_transcript,
	})
}

fn verify_live(
	case: &BenchCase,
) -> Result<(verifier_ring_switch::RingSwitchVerifyOutput<F>, verifier_basefold::ReducedOutput<F>, F)>
{
	let mut transcript =
		VerifierTranscript::new(StdChallenger::default(), case.proof_bytes.clone());
	let codeword_commitment: MerkleDigest = transcript.message().read()?;
	let ring_switch_output =
		verifier_ring_switch::verify(case.evaluation_claim, &case.eval_point, &mut transcript)?;
	let basefold_output = verifier_basefold::verify(
		&case.fri_params,
		&case.merkle_scheme,
		codeword_commitment,
		ring_switch_output.sumcheck_claim,
		&mut transcript,
	)?;
	let opened = basefold_output.opened_linear_relation();
	let transparent_eval = ring_switch_output.relation.eval(&opened.query_point);

	Ok((ring_switch_output, basefold_output, transparent_eval))
}

fn normalize_live_output(
	ring_switch_output: verifier_ring_switch::RingSwitchVerifyOutput<F>,
	basefold_output: verifier_basefold::ReducedOutput<F>,
	transparent_eval: F,
) -> pcs_extract::ExtractPcsOpeningOutput {
	let verifier_basefold::OpenedLinearRelationWithSampling { opened, sampling } =
		basefold_output.into_opened_linear_relation_with_sampling();
	binius_verifier::pcs::PcsOpeningOutput::<F, verifier_ring_switch::RingSwitchEqRelation<F>> {
		relation: ring_switch_output.relation,
		sumcheck_claim: ring_switch_output.sumcheck_claim,
		opened,
		sampling,
		transparent_eval,
	}
	.into()
}

fn verify_replay_preparsed(case: &BenchCase) -> Result<pcs_extract::ExtractPcsOpeningOutput> {
	let replay = case
		.extract_statement
		.verify_transcript(&case.extract_transcript)
	.map_err(|err| anyhow::anyhow!("replay verification failed: {err:?}"))?;
	Ok(replay)
}

fn verify_replay_with_parse(case: &BenchCase) -> Result<pcs_extract::ExtractPcsOpeningOutput> {
	let (extract_commitment, ring_switch_transcript, basefold_transcript) =
		extract_scripted_inputs(&case.fri_params, &case.merkle_scheme, case.proof_bytes.clone())?;
	let extract_statement = pcs_extract::ExtractPcsStatement {
		params: extract_fri_params(&case.fri_params, &case.merkle_scheme),
		codeword_commitment: extract_commitment,
		witness_eval: case.evaluation_claim,
		eval_point: case.eval_point.clone(),
	};
	let extract_transcript = pcs_extract::ExtractPcsTranscriptView {
		ring_switch: ring_switch_transcript,
		basefold: basefold_transcript,
	};
	let replay = extract_statement
		.verify_transcript(&extract_transcript)
	.map_err(|err| anyhow::anyhow!("replay verification failed: {err:?}"))?;
	Ok(replay)
}

#[test]
fn pcs_extract_matches_transcript_backed_slice() -> Result<()> {
	let case = make_bench_case()?;
	let (live_ring_switch, live_basefold, live_transparent_eval) = verify_live(&case)?;
	let live = normalize_live_output(live_ring_switch, live_basefold, live_transparent_eval);
	let replay = verify_replay_preparsed(&case)?;

	assert_eq!(replay, live);

	Ok(())
}

#[test]
fn pcs_extract_rejects_corrupted_ring_switch_input() -> Result<()> {
	let case = make_bench_case()?;
	let mut extract_transcript = case.extract_transcript.clone();
	extract_transcript.ring_switch.proof.messages[0] += F::ONE;

	let replay =
		case.extract_statement.verify_transcript(&extract_transcript);

	assert_eq!(replay, Err(pcs_extract::ExtractError::RingSwitchFailure));
	Ok(())
}

#[test]
fn pcs_extract_rejects_corrupted_basefold_opening() -> Result<()> {
	let case = make_bench_case()?;
	let mut extract_transcript = case.extract_transcript.clone();
	extract_transcript.basefold.proof.merkle_openings[0].values[0] += F::ONE;

	let replay =
		case.extract_statement.verify_transcript(&extract_transcript);

	assert_eq!(replay, Err(pcs_extract::ExtractError::BaseFoldFailure));
	Ok(())
}

#[test]
#[ignore = "performance probe; run explicitly with --ignored --nocapture"]
fn pcs_extract_perf_report() -> Result<()> {
	let case = make_bench_case()?;
	let iters = 2_000usize;

	for _ in 0..32 {
		black_box(verify_live(&case)?);
		black_box(verify_replay_preparsed(&case)?);
		black_box(verify_replay_with_parse(&case)?);
	}

	let start = Instant::now();
	for _ in 0..iters {
		black_box(verify_live(&case)?);
	}
	let live = start.elapsed();

	let start = Instant::now();
	for _ in 0..iters {
		black_box(verify_replay_preparsed(&case)?);
	}
	let replay_preparsed = start.elapsed();

	let start = Instant::now();
	for _ in 0..iters {
		black_box(verify_replay_with_parse(&case)?);
	}
	let replay_with_parse = start.elapsed();

	let live_us = live.as_secs_f64() * 1_000_000.0 / iters as f64;
	let replay_preparsed_us = replay_preparsed.as_secs_f64() * 1_000_000.0 / iters as f64;
	let replay_with_parse_us = replay_with_parse.as_secs_f64() * 1_000_000.0 / iters as f64;

	println!("live transcript-backed verify: {live_us:.2} us/run");
	println!(
		"replay verify (pre-parsed inputs): {replay_preparsed_us:.2} us/run ({:.3}x live)",
		replay_preparsed_us / live_us
	);
	println!(
		"replay verify (parse + verify): {replay_with_parse_us:.2} us/run ({:.3}x live)",
		replay_with_parse_us / live_us
	);

	Ok(())
}
