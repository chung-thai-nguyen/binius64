// Copyright 2024-2025 Irreducible Inc.

use std::iter;

use binius_field::BinaryField;
use binius_math::{
	FieldBuffer,
	multilinear::eq::eq_ind_partial_eval,
	ntt::{AdditiveNTT, NeighborsLastSingleThread, domain_context::GenericOnTheFly},
};
use binius_transcript::{
	TranscriptReader, VerifierTranscript,
	fiat_shamir::{CanSampleBits, Challenger},
};
use binius_utils::DeserializeBytes;
use bytes::Buf;
use itertools::izip;

use super::{
	common::{FRIParams, vcs_optimal_layers_depths_iter},
	error::{Error, VerificationError},
};
use crate::{
	fri::fold::{fold_chunk, fold_interleaved_chunk},
	merkle_tree::MerkleTreeScheme,
};

/// Explicit opened state for the FRI query phase.
#[derive(Debug, Clone)]
pub struct OpenedFRIQueryPhase<F, D> {
	pub final_value: F,
	pub query_indices: Vec<usize>,
	pub terminate_codeword: Vec<F>,
	pub layers: Vec<Vec<D>>,
}

/// Authenticated FRI proof material after Merkle-opening checks but before fold/degree semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedFRIQueryPhase<F, D> {
	pub query_indices: Vec<usize>,
	pub terminate_codeword: Vec<F>,
	pub layers: Vec<Vec<D>>,
	pub opened_queries: Vec<OpenedFRIQuery<F>>,
}

/// Opened values for one FRI challenge query, after commitment authentication but before semantic
/// fold-consistency checking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedFRIQuery<F> {
	pub initial_index: usize,
	pub first_values: Vec<F>,
	pub fold_values: Vec<Vec<F>>,
}

/// Pure FRI semantic verifier over already-authenticated query material.
#[derive(Debug, Clone)]
pub struct FRISemanticVerifier<'a, F>
where
	F: BinaryField,
{
	params: &'a FRIParams<F>,
	interleave_tensor: FieldBuffer<F>,
	fold_challenges: &'a [F],
}

impl<'a, F> FRISemanticVerifier<'a, F>
where
	F: BinaryField,
{
	pub fn new(params: &'a FRIParams<F>, challenges: &'a [F]) -> Result<Self, Error> {
		if challenges.len() != params.n_fold_rounds() {
			return Err(Error::InvalidArgs(format!(
				"got {} folding challenges, expected {}",
				challenges.len(),
				params.n_fold_rounds(),
			)));
		}

		let (interleave_challenges, fold_challenges) = challenges.split_at(params.log_batch_size());
		let interleave_tensor = eq_ind_partial_eval(interleave_challenges);
		Ok(Self {
			params,
			interleave_tensor,
			fold_challenges,
		})
	}

	pub fn verify_authenticated_phase<D>(
		&self,
		ntt: &impl AdditiveNTT<Field = F>,
		authenticated: AuthenticatedFRIQueryPhase<F, D>,
	) -> Result<OpenedFRIQueryPhase<F, D>, Error>
	where
		D: Clone,
	{
		let final_value = self.verify_last_oracle_values(ntt, &authenticated.terminate_codeword)?;
		for opened_query in &authenticated.opened_queries {
			self.verify_opened_query(opened_query.clone(), ntt, &authenticated.terminate_codeword)?;
		}

		Ok(OpenedFRIQueryPhase {
			final_value,
			query_indices: authenticated.query_indices,
			terminate_codeword: authenticated.terminate_codeword,
			layers: authenticated.layers,
		})
	}

	pub fn verify_last_oracle_values(
		&self,
		ntt: &impl AdditiveNTT<Field = F>,
		terminate_codeword: &[F],
	) -> Result<F, Error> {
		let n_final_challenges = self.params.n_final_challenges();
		let n_prior_challenges = self.fold_challenges.len() - n_final_challenges;
		let final_challenges = &self.fold_challenges[n_prior_challenges..];

		let mut scratch_buffer = vec![F::default(); 1 << n_final_challenges];
		let repetition_codeword = terminate_codeword
			.chunks(1 << n_final_challenges)
			.enumerate()
			.map(|(i, coset_values)| {
				scratch_buffer.copy_from_slice(coset_values);
				fold_chunk(
					ntt,
					n_final_challenges + self.params.rs_code().log_inv_rate(),
					i,
					&mut scratch_buffer,
					final_challenges,
				)
			})
			.collect::<Vec<_>>();

		let final_value = repetition_codeword[0];

		if repetition_codeword[1..]
			.iter()
			.any(|&entry| entry != final_value)
		{
			return Err(VerificationError::IncorrectDegree.into());
		}

		Ok(final_value)
	}

	pub fn verify_opened_query(
		&self,
		query: OpenedFRIQuery<F>,
		ntt: &impl AdditiveNTT<Field = F>,
		terminate_codeword: &[F],
	) -> Result<(), Error> {
		let mut index = query.initial_index;
		let mut next_value = fold_interleaved_chunk(
			self.params.log_batch_size(),
			&query.first_values,
			self.interleave_tensor.as_ref(),
		);

		let mut fold_round = 0;
		for (i, (&arity, mut values)) in
			izip!(self.params.fold_arities(), query.fold_values.into_iter()).enumerate()
		{
			let coset_index = index >> arity;

			if next_value != values[index % (1 << arity)] {
				return Err(VerificationError::IncorrectFold {
					query_round: i,
					index,
				}
				.into());
			}

			next_value = fold_chunk(
				ntt,
				self.params.rs_code().log_len() - fold_round,
				coset_index,
				&mut values,
				&self.fold_challenges[fold_round..fold_round + arity],
			);
			fold_round += arity;
			index = coset_index;
		}

		if next_value != terminate_codeword[index] {
			return Err(VerificationError::IncorrectFold {
				query_round: self.params.n_oracles() - 1,
				index,
			}
			.into());
		}

		Ok(())
	}
}

/// A verifier for the FRI query phase.
///
/// The verifier is instantiated after the folding rounds and is used to test consistency of the
/// round messages and the original purported codeword.
#[derive(Debug)]
pub struct FRIQueryVerifier<'a, F, VCS>
where
	F: BinaryField,
	VCS: MerkleTreeScheme<F>,
{
	vcs: &'a VCS,
	params: &'a FRIParams<F>,
	/// Received commitment to the codeword.
	codeword_commitment: &'a VCS::Digest,
	/// Received commitments to the round messages.
	round_commitments: &'a [VCS::Digest],
	/// Pure semantic verifier over the authenticated FRI query phase.
	semantic_verifier: FRISemanticVerifier<'a, F>,
}

impl<'a, F, VCS> FRIQueryVerifier<'a, F, VCS>
where
	F: BinaryField,
	VCS: MerkleTreeScheme<F, Digest: DeserializeBytes>,
{
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		params: &'a FRIParams<F>,
		vcs: &'a VCS,
		codeword_commitment: &'a VCS::Digest,
		round_commitments: &'a [VCS::Digest],
		challenges: &'a [F],
	) -> Result<Self, Error> {
		if round_commitments.len() != params.n_oracles() {
			return Err(Error::InvalidArgs(format!(
				"got {} round commitments, expected {}",
				round_commitments.len(),
				params.n_oracles(),
			)));
		}

		if challenges.len() != params.n_fold_rounds() {
			return Err(Error::InvalidArgs(format!(
				"got {} folding challenges, expected {}",
				challenges.len(),
				params.n_fold_rounds(),
			)));
		}

		Ok(Self {
			params,
			vcs,
			codeword_commitment,
			round_commitments,
			semantic_verifier: FRISemanticVerifier::new(params, challenges)?,
		})
	}

	/// Number of oracles sent during the fold rounds.
	pub fn n_oracles(&self) -> usize {
		self.params.n_oracles()
	}

	pub fn verify<Challenger_>(
		&self,
		transcript: &mut VerifierTranscript<Challenger_>,
	) -> Result<F, Error>
	where
		Challenger_: Challenger,
	{
		self.verify_opened(transcript).map(|opened| opened.final_value)
	}

	pub fn verify_opened<Challenger_>(
		&self,
		transcript: &mut VerifierTranscript<Challenger_>,
	) -> Result<OpenedFRIQueryPhase<F, VCS::Digest>, Error>
	where
		Challenger_: Challenger,
	{
		let subspace = self.params.rs_code().subspace();
		let domain_context = GenericOnTheFly::generate_from_subspace(subspace);
		let ntt = NeighborsLastSingleThread::new(domain_context);
		let authenticated = self.open_phase(transcript)?;
		Ok(self.semantic_verifier.verify_authenticated_phase(&ntt, authenticated)?)
	}

	pub fn open_phase<Challenger_>(
		&self,
		transcript: &mut VerifierTranscript<Challenger_>,
	) -> Result<AuthenticatedFRIQueryPhase<F, VCS::Digest>, Error>
	where
		Challenger_: Challenger,
	{
		let mut query_indices = Vec::with_capacity(self.params.n_test_queries());
		let mut opened_queries = Vec::with_capacity(self.params.n_test_queries());

		let terminate_codeword_len =
			1 << (self.params.n_final_challenges() + self.params.rs_code().log_inv_rate());
		let mut advice = transcript.decommitment();
		let terminate_codeword = advice
			.read_scalar_slice(terminate_codeword_len)
			.map_err(Error::TranscriptError)?;
		self.open_last_oracle(&terminate_codeword, &mut advice)?;

		let layers = vcs_optimal_layers_depths_iter(self.params, self.vcs)
			.map(|layer_depth| advice.read_vec(1 << layer_depth))
			.collect::<Result<Vec<_>, _>>()?;
		for (commitment, layer_depth, layer) in izip!(
			iter::once(self.codeword_commitment).chain(self.round_commitments),
			vcs_optimal_layers_depths_iter(self.params, self.vcs),
			&layers
		) {
			self.vcs.verify_layer(commitment, layer_depth, layer)?;
		}

		for _ in 0..self.params.n_test_queries() {
			let index = transcript.sample_bits(self.params.index_bits()) as usize;
			query_indices.push(index);
			let opened_query = self.open_query(index, &layers, &mut transcript.decommitment())?;
			opened_queries.push(opened_query);
		}

		Ok(AuthenticatedFRIQueryPhase {
			query_indices,
			terminate_codeword,
			layers,
			opened_queries,
		})
	}

	pub fn verify_authenticated_phase(
		&self,
		ntt: &impl AdditiveNTT<Field = F>,
		authenticated: AuthenticatedFRIQueryPhase<F, VCS::Digest>,
	) -> Result<OpenedFRIQueryPhase<F, VCS::Digest>, Error> {
		self.semantic_verifier
			.verify_authenticated_phase(ntt, authenticated)
	}

	/// Verify only the Merkle-opening side of the final oracle.
	pub fn open_last_oracle<B: Buf>(
		&self,
		terminate_codeword: &[F],
		advice: &mut TranscriptReader<B>,
	) -> Result<(), Error> {
		let terminal_commitment = self
			.round_commitments
			.last()
			.expect("round_commitments is non-empty as an invariant");

		self.vcs.verify_vector(
			terminal_commitment,
			terminate_codeword,
			1 << self.params.n_final_challenges(),
			advice,
		)?;
		Ok(())
	}

	/// Verify only the FRI/degree semantics of the final oracle, assuming authentication already
	/// succeeded.
	pub fn verify_last_oracle_values(
		&self,
		ntt: &impl AdditiveNTT<Field = F>,
		terminate_codeword: &[F],
	) -> Result<F, Error> {
		self.semantic_verifier
			.verify_last_oracle_values(ntt, terminate_codeword)
	}

	/// Verifies that the last oracle sent is a codeword.
	///
	/// Returns the fully-folded message value.
	pub fn verify_last_oracle<B: Buf>(
		&self,
		ntt: &impl AdditiveNTT<Field = F>,
		terminate_codeword: &[F],
		advice: &mut TranscriptReader<B>,
	) -> Result<F, Error> {
		self.open_last_oracle(terminate_codeword, advice)?;
		self.verify_last_oracle_values(ntt, terminate_codeword)
	}

	/// Verifies a FRI challenge query.
	///
	/// A FRI challenge query tests for consistency between all consecutive oracles sent by the
	/// prover. The verifier has full access to the last oracle sent, and this is probabilistically
	/// verified to be a codeword by `Self::verify_last_oracle`.
	///
	/// ## Arguments
	///
	/// * `index` - an index into the original codeword domain
	/// * `proof` - a query proof
	pub fn verify_query<B: Buf>(
		&self,
		index: usize,
		ntt: &impl AdditiveNTT<Field = F>,
		terminate_codeword: &[F],
		layers: &[Vec<VCS::Digest>],
		advice: &mut TranscriptReader<B>,
	) -> Result<(), Error> {
		let opened_query = self.open_query(index, layers, advice)?;
		self.verify_opened_query(opened_query, ntt, terminate_codeword)
	}

	pub fn open_query<B: Buf>(
		&self,
		mut index: usize,
		layers: &[Vec<VCS::Digest>],
		advice: &mut TranscriptReader<B>,
	) -> Result<OpenedFRIQuery<F>, Error>
	where
		B: Buf,
	{
		let mut layer_depths_iter = vcs_optimal_layers_depths_iter(self.params, self.vcs);
		let mut layers_iter = layers.iter();
		let initial_index = index;

		// Check the first fold round before the main loop. It is special because in the first
		// round we need to fold as an interleaved chunk instead of a regular coset.
		let first_layer_depth = layer_depths_iter
			.next()
			.expect("protocol guarantees at least one commitment opening");
		let first_layer = layers_iter
			.next()
			.expect("protocol guarantees at least one commitment opening");
		let values = verify_coset_opening(
			self.vcs,
			index,
			self.params.log_batch_size(),
			first_layer_depth,
			self.params.index_bits(),
			first_layer,
			advice,
		)?;
		let first_values = values;

		// This is the round of the folding phase that the codeword to be folded is committed to.
		let mut log_n_cosets = self.params.index_bits();
		let mut fold_values = Vec::with_capacity(self.params.fold_arities().len());
		for (i, (&arity, layer, optimal_layer_depth)) in
			izip!(self.params.fold_arities(), layers_iter, layer_depths_iter).enumerate()
		{
			let coset_index = index >> arity;
			log_n_cosets -= arity;

			let values = verify_coset_opening(
				self.vcs,
				coset_index,
				arity,
				optimal_layer_depth,
				log_n_cosets,
				layer,
				advice,
			)?;
			fold_values.push(values);
			index = coset_index;
			let _ = i;
		}

		Ok(OpenedFRIQuery {
			initial_index,
			first_values,
			fold_values,
		})
	}

	pub fn verify_opened_query(
		&self,
		query: OpenedFRIQuery<F>,
		ntt: &impl AdditiveNTT<Field = F>,
		terminate_codeword: &[F],
	) -> Result<(), Error> {
		self.semantic_verifier
			.verify_opened_query(query, ntt, terminate_codeword)
	}
}

/// Verifies that the coset opening provided in the proof is consistent with the VCS commitment.
#[allow(clippy::too_many_arguments)]
fn verify_coset_opening<F, MTScheme, B>(
	vcs: &MTScheme,
	coset_index: usize,
	log_coset_size: usize,
	optimal_layer_depth: usize,
	tree_depth: usize,
	layer_digests: &[MTScheme::Digest],
	advice: &mut TranscriptReader<B>,
) -> Result<Vec<F>, Error>
where
	F: BinaryField,
	MTScheme: MerkleTreeScheme<F>,
	B: Buf,
{
	let values = advice.read_scalar_slice::<F>(1 << log_coset_size)?;
	vcs.verify_opening(
		coset_index,
		&values,
		optimal_layer_depth,
		tree_depth,
		layer_digests,
		advice,
	)?;
	Ok(values)
}
