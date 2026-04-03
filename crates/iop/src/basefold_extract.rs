// Copyright 2026 The Binius Developers

//! Extraction-oriented scripted BaseFold verifier.
//!
//! This module provides a monomorphic, plain-data replay of the BaseFold / FRI verifier slice.
//! It is intended for extraction experiments where the live verifier's transcript, Merkle scheme,
//! and generic field interfaces are too rich for current extraction tools.

use binius_field::BinaryField128bGhash;

use crate::basefold::ReducedOutput;
use crate::fri::verify::{AuthenticatedFRIQueryPhase, OpenedFRIQuery, OpenedFRIQueryPhase};
use crate::protocol_boundary::{
	AuthenticatedStatementTranscriptProtocol, StatementTranscriptProtocol,
};

pub trait F: Copy + Clone + PartialEq {
    const ZERO: Self;
    const ONE: Self;
    fn add(self, rhs: Self) -> Self;
    fn mul(self, rhs: Self) -> Self;
    fn sub(self, rhs: Self) -> Self;
}

impl<T: binius_field::Field> F for T {
    const ZERO: Self = <T as binius_field::Field>::ZERO;
    const ONE: Self = <T as binius_field::Field>::ONE;
    fn add(self, rhs: Self) -> Self { self + rhs }
    fn mul(self, rhs: Self) -> Self { self * rhs }
    fn sub(self, rhs: Self) -> Self { self - rhs }
}
pub type ExtractDigest = [u8; 32];

/// Monomorphic verifier randomness used by the extraction-oriented BaseFold / FRI opening path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractSamplingTrace<F: ExtractField> {
	pub challenges: Vec<ExtractField>,
	pub query_indices: Vec<usize>,
}

/// Monomorphic semantic opening object produced by the extraction-oriented BaseFold / FRI path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractOpenedLinearRelation<F: ExtractField> {
	pub final_fri_value: F,
	pub final_sumcheck_value: F,
	pub query_point: Vec<ExtractField>,
}

/// Monomorphic opening object paired with the verifier randomness used to obtain it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractOpenedLinearRelationWithSampling<F: ExtractField> {
	pub opened: ExtractOpenedLinearRelation<F>,
	pub sampling: ExtractSamplingTrace<F>,
}

/// Monomorphic BaseFold / FRI reduced opening output exported to Hax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractReducedOutput<F: ExtractField> {
	pub final_fri_value: F,
	pub final_sumcheck_value: F,
	pub sampling: ExtractSamplingTrace<F>,
}

/// Monomorphic authenticated BaseFold / FRI opening after transcript / Merkle checks but before
/// the pure IOP semantic finalization step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractAuthenticatedLinearRelationOpening<F: ExtractField> {
	pub final_sumcheck_value: F,
	pub sampling: ExtractSamplingTrace<F>,
	pub query_phase: AuthenticatedFRIQueryPhase<F, ExtractDigest>,
	pub query_challenge_offset: usize,
}

/// Monomorphic BaseFold / FRI statement exported to Hax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractBasefoldStatement<F: ExtractField> {
	pub params: ExtractFriParams,
	pub codeword_commitment: ExtractDigest,
	pub evaluation_claim: F,
}

/// Monomorphic prover-message view for BaseFold / FRI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractBasefoldProofView<F: ExtractField> {
	pub round_coeffs: Vec<[F; 2]>,
	pub commitments: Vec<ExtractDigest>,
	pub decommitment_scalars: Vec<Vec<ExtractField>>,
	pub decommitments: Vec<Vec<ExtractDigest>>,
	pub merkle_vectors: Vec<ExtractMerkleVector>,
	pub merkle_openings: Vec<ExtractMerkleOpening>,
	pub merkle_layers: Vec<ExtractMerkleLayer>,
}

/// Monomorphic verifier-randomness view for BaseFold / FRI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractBasefoldSamplingView<F: ExtractField> {
	pub challenges: Vec<ExtractField>,
	pub query_indices: Vec<usize>,
}

/// Monomorphic public-coin interaction view for BaseFold / FRI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractBasefoldTranscriptView<F: ExtractField> {
	pub proof: ExtractBasefoldProofView<F>,
	pub sampling: ExtractBasefoldSamplingView<F>,
}

/// Thin protocol-boundary marker for the extraction-oriented BaseFold / FRI verifier.
pub struct ExtractBasefoldProtocol<F: ExtractField>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractFriParams {
	pub log_msg_len: usize,
	pub log_batch_size: usize,
	pub fold_arities: Vec<usize>,
	pub index_bits: usize,
	pub log_inv_rate: usize,
	pub n_final_challenges: usize,
	pub n_test_queries: usize,
	pub layer_depths: Vec<usize>,
	pub twiddle_evals: Vec<Vec<ExtractField>>,
}

impl ExtractFriParams {
	pub fn n_oracles(&self) -> usize {
		1 + self.fold_arities.len()
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
	MissingObject,
	IncorrectProofShape,
	UnconsumedTranscript,
	MerkleVectorMismatch,
	MerkleOpeningMismatch,
	MerkleLayerMismatch,
	IncorrectFold { query_round: usize, index: usize },
	IncorrectDegree,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractMerkleVector {
	pub root: ExtractDigest,
	pub data: Vec<ExtractField>,
	pub batch_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractMerkleOpening {
	pub index: usize,
	pub values: Vec<ExtractField>,
	pub layer_depth: usize,
	pub tree_depth: usize,
	pub layer_digests: Vec<ExtractDigest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractMerkleLayer {
	pub root: ExtractDigest,
	pub layer_depth: usize,
	pub layer_digests: Vec<ExtractDigest>,
}

#[derive(Debug, Clone, Default)]
pub struct ExtractProofOracle {
	pub round_coeffs: Vec<[F; 2]>,
	pub commitments: Vec<ExtractDigest>,
	pub decommitment_scalars: Vec<Vec<ExtractField>>,
	pub decommitments: Vec<Vec<ExtractDigest>>,
	pub challenges: Vec<ExtractField>,
	pub query_indices: Vec<usize>,
	pub merkle_vectors: Vec<ExtractMerkleVector>,
	pub merkle_openings: Vec<ExtractMerkleOpening>,
	pub merkle_layers: Vec<ExtractMerkleLayer>,

	round_coeffs_pos: usize,
	commitments_pos: usize,
	decommitment_scalars_pos: usize,
	decommitments_pos: usize,
	challenges_pos: usize,
	query_indices_pos: usize,
	merkle_vectors_pos: usize,
	merkle_openings_pos: usize,
	merkle_layers_pos: usize,
}

impl ExtractProofOracle {
	pub fn read_round_coeffs(&mut self) -> Result<[F; 2], ExtractError> {
		if let Some(value) = self.round_coeffs.get(self.round_coeffs_pos) {
			self.round_coeffs_pos += 1;
			Ok(*value)
		} else {
			Err(ExtractError::MissingObject)
		}
	}

	pub fn read_commitment(&mut self) -> Result<ExtractDigest, ExtractError> {
		if let Some(value) = self.commitments.get(self.commitments_pos) {
			self.commitments_pos += 1;
			Ok(*value)
		} else {
			Err(ExtractError::MissingObject)
		}
	}

	pub fn read_commitment_vec(&mut self, n: usize) -> Result<Vec<ExtractDigest>, ExtractError> {
		if let Some(value_ref) = self.decommitments.get(self.decommitments_pos) {
			let value = value_ref.clone();
			self.decommitments_pos += 1;
			if value.len() == n {
				Ok(value)
			} else {
				Err(ExtractError::IncorrectProofShape)
			}
		} else {
			Err(ExtractError::MissingObject)
		}
	}

	pub fn read_decommitment_scalars(
		&mut self,
		n: usize,
	) -> Result<Vec<ExtractField>, ExtractError> {
		if let Some(value_ref) = self.decommitment_scalars.get(self.decommitment_scalars_pos) {
			let value = value_ref.clone();
			self.decommitment_scalars_pos += 1;
			if value.len() == n {
				Ok(value)
			} else {
				Err(ExtractError::IncorrectProofShape)
			}
		} else {
			Err(ExtractError::MissingObject)
		}
	}

	pub fn sample_challenge(&mut self) -> Result<F, ExtractError> {
		if let Some(value) = self.challenges.get(self.challenges_pos) {
			self.challenges_pos += 1;
			Ok(*value)
		} else {
			Err(ExtractError::MissingObject)
		}
	}

	pub fn sample_query_index(&mut self) -> Result<usize, ExtractError> {
		if let Some(value) = self.query_indices.get(self.query_indices_pos) {
			self.query_indices_pos += 1;
			Ok(*value)
		} else {
			Err(ExtractError::MissingObject)
		}
	}

	pub fn read_merkle_vector(
		&mut self,
		value_len: usize,
	) -> Result<ExtractMerkleVector, ExtractError> {
		let data = self.read_decommitment_scalars(value_len)?;
		if let Some(expected_ref) = self.merkle_vectors.get(self.merkle_vectors_pos) {
			let expected = expected_ref.clone();
			self.merkle_vectors_pos += 1;
			if expected.data.len() != value_len {
				return Err(ExtractError::IncorrectProofShape);
			}
			if expected.data != data {
				return Err(ExtractError::MerkleVectorMismatch);
			}
			Ok(expected)
		} else {
			Err(ExtractError::MissingObject)
		}
	}

	pub fn read_merkle_opening(
		&mut self,
		value_len: usize,
	) -> Result<ExtractMerkleOpening, ExtractError> {
		let values = self.read_decommitment_scalars(value_len)?;
		if let Some(expected_ref) = self.merkle_openings.get(self.merkle_openings_pos) {
			let expected = expected_ref.clone();
			self.merkle_openings_pos += 1;
			if expected.values.len() != value_len {
				return Err(ExtractError::IncorrectProofShape);
			}
			if expected.values != values {
				return Err(ExtractError::MerkleOpeningMismatch);
			}
			Ok(expected)
		} else {
			Err(ExtractError::MissingObject)
		}
	}

	pub fn read_merkle_layer(
		&mut self,
		layer_size: usize,
	) -> Result<ExtractMerkleLayer, ExtractError> {
		let layer_digests = self.read_commitment_vec(layer_size)?;
		if let Some(expected_ref) = self.merkle_layers.get(self.merkle_layers_pos) {
			let expected = expected_ref.clone();
			self.merkle_layers_pos += 1;
			if expected.layer_digests.len() != layer_size {
				return Err(ExtractError::IncorrectProofShape);
			}
			if expected.layer_digests != layer_digests {
				return Err(ExtractError::MerkleLayerMismatch);
			}
			Ok(expected)
		} else {
			Err(ExtractError::MissingObject)
		}
	}

	pub fn is_consumed(&self) -> bool {
		self.round_coeffs_pos == self.round_coeffs.len()
			&& self.commitments_pos == self.commitments.len()
			&& self.decommitment_scalars_pos == self.decommitment_scalars.len()
			&& self.decommitments_pos == self.decommitments.len()
			&& self.challenges_pos == self.challenges.len()
			&& self.query_indices_pos == self.query_indices.len()
			&& self.merkle_vectors_pos == self.merkle_vectors.len()
			&& self.merkle_openings_pos == self.merkle_openings.len()
			&& self.merkle_layers_pos == self.merkle_layers.len()
	}
}

impl From<&ExtractBasefoldTranscriptView<F>> for ExtractProofOracle {
	fn from(value: &ExtractBasefoldTranscriptView<F>) -> Self {
		Self {
			round_coeffs: value.proof.round_coeffs.clone(),
			commitments: value.proof.commitments.clone(),
			decommitment_scalars: value.proof.decommitment_scalars.clone(),
			decommitments: value.proof.decommitments.clone(),
			challenges: value.sampling.challenges.clone(),
			query_indices: value.sampling.query_indices.clone(),
			merkle_vectors: value.proof.merkle_vectors.clone(),
			merkle_openings: value.proof.merkle_openings.clone(),
			merkle_layers: value.proof.merkle_layers.clone(),
			round_coeffs_pos: 0,
			commitments_pos: 0,
			decommitment_scalars_pos: 0,
			decommitments_pos: 0,
			challenges_pos: 0,
			query_indices_pos: 0,
			merkle_vectors_pos: 0,
			merkle_openings_pos: 0,
			merkle_layers_pos: 0,
		}
	}
}

impl<F: ExtractField> ExtractReducedOutput<F> {
	pub fn sampling_trace(&self) -> ExtractSamplingTrace<F> {
		self.sampling.clone()
	}

	pub fn opened_linear_relation(&self) -> ExtractOpenedLinearRelation<F> {
		ExtractOpenedLinearRelation<F> {
			final_fri_value: self.final_fri_value,
			final_sumcheck_value: self.final_sumcheck_value,
			query_point: crate::basefold::query_point_from_challenges(&self.sampling.challenges),
		}
	}

	pub fn opened_linear_relation_with_sampling(&self) -> ExtractOpenedLinearRelationWithSampling<F> {
		ExtractOpenedLinearRelationWithSampling<F> {
			opened: self.opened_linear_relation(),
			sampling: self.sampling_trace(),
		}
	}

	pub fn into_opened_linear_relation_with_sampling(self) -> ExtractOpenedLinearRelationWithSampling<F> {
		let query_point = crate::basefold::query_point_from_challenges(&self.sampling.challenges);
		ExtractOpenedLinearRelationWithSampling<F> {
			opened: ExtractOpenedLinearRelation<F> {
				final_fri_value: self.final_fri_value,
				final_sumcheck_value: self.final_sumcheck_value,
				query_point,
			},
			sampling: self.sampling,
		}
	}
}

impl From<ReducedOutput<ExtractField>> for ExtractReducedOutput<F> {
	fn from(value: ReducedOutput<ExtractField>) -> Self {
		Self {
			final_fri_value: value.final_fri_value,
			final_sumcheck_value: value.final_sumcheck_value,
			sampling: ExtractSamplingTrace<F> {
				challenges: value.challenges,
				query_indices: value.query_indices,
			},
		}
	}
}

impl<F: ExtractField> ExtractBasefoldStatement<F> {
	pub fn verify_transcript(
		&self,
		transcript: &ExtractBasefoldTranscriptView<F>,
	) -> Result<ExtractReducedOutput<F>, ExtractError> {
		ExtractBasefoldProtocol<F>::verify_statement_transcript(self, transcript)
	}

	pub fn verify_authenticated_transcript(
		&self,
		transcript: &ExtractBasefoldTranscriptView<F>,
	) -> Result<ExtractAuthenticatedLinearRelationOpening<F>, ExtractError> {
		ExtractBasefoldProtocol<F>::verify_authenticated_statement_transcript(self, transcript)
	}

	pub fn verify_authenticated(
		&self,
		authenticated: ExtractAuthenticatedLinearRelationOpening<F>,
	) -> Result<ExtractReducedOutput<F>, ExtractError> {
		ExtractBasefoldProtocol<F>::verify_authenticated(self, authenticated)
	}

	pub fn finalize_authenticated(
		&self,
		authenticated: ExtractAuthenticatedLinearRelationOpening<F>,
	) -> Result<ExtractOpenedLinearRelationWithSampling<F>, ExtractError> {
		finalize_authenticated_extract(&self.params, authenticated)
	}
}

impl AuthenticatedStatementTranscriptProtocol for ExtractBasefoldProtocol<F> {
	type Statement = ExtractBasefoldStatement<F>;
	type TranscriptView = ExtractBasefoldTranscriptView<F>;
	type Authenticated = ExtractAuthenticatedLinearRelationOpening<F>;
	type Output = ExtractReducedOutput<F>;
	type Error = ExtractError;

	fn verify_authenticated_statement_transcript(
		statement: &Self::Statement,
		transcript: &Self::TranscriptView,
	) -> Result<Self::Authenticated, Self::Error> {
		verify_authenticated_statement_transcript_extract(statement, transcript)
	}

	fn verify_authenticated(
		statement: &Self::Statement,
		authenticated: Self::Authenticated,
	) -> Result<Self::Output, Self::Error> {
		verify_authenticated_extract(&statement.params, authenticated)
	}
}

pub fn verify_statement_transcript_extract(
	statement: &ExtractBasefoldStatement<F>,
	transcript: &ExtractBasefoldTranscriptView<F>,
) -> Result<ExtractReducedOutput<F>, ExtractError> {
	let authenticated =
		verify_authenticated_statement_transcript_extract(statement, transcript)?;
	verify_authenticated_extract(&statement.params, authenticated)
}

pub fn verify_authenticated_statement_transcript_extract(
	statement: &ExtractBasefoldStatement<F>,
	transcript: &ExtractBasefoldTranscriptView<F>,
) -> Result<ExtractAuthenticatedLinearRelationOpening<F>, ExtractError> {
	let mut oracle = ExtractProofOracle::from(transcript);
	let output = open_authenticated_extract(
		&statement.params,
		statement.codeword_commitment,
		statement.evaluation_claim,
		&mut oracle,
	)?;
	if oracle.is_consumed() {
		Ok(output)
	} else {
		Err(ExtractError::UnconsumedTranscript)
	}
}

pub fn verify_scripted_extract(
	params: &ExtractFriParams,
	codeword_commitment: ExtractDigest,
	evaluation_claim: F,
	oracle: &mut ExtractProofOracle,
) -> Result<ExtractReducedOutput<F>, ExtractError> {
	let authenticated =
		open_authenticated_extract(params, codeword_commitment, evaluation_claim, oracle)?;
	verify_authenticated_extract(params, authenticated)
}

pub fn open_authenticated_extract(
	params: &ExtractFriParams,
	codeword_commitment: ExtractDigest,
	evaluation_claim: F,
	oracle: &mut ExtractProofOracle,
) -> Result<ExtractAuthenticatedLinearRelationOpening<F>, ExtractError> {
	let n_vars = params.log_msg_len;
	let commitment_rounds =
		calculate_fri_commit_rounds(params.log_batch_size, &params.fold_arities, n_vars + 1);
	let mut round_commitments = Vec::with_capacity(params.n_oracles());
	let mut challenges = Vec::with_capacity(n_vars);
	let mut sum = evaluation_claim;

	for round in 0..n_vars {
		let round_coeffs = recover_round_coeffs(sum, oracle.read_round_coeffs()?);
		if commitment_rounds[round] {
			round_commitments.push(oracle.read_commitment()?);
		}
		let challenge = oracle.sample_challenge()?;
		sum = evaluate_round_coeffs(round_coeffs, challenge);
		challenges.push(challenge);
	}

	if commitment_rounds[n_vars] {
		round_commitments.push(oracle.read_commitment()?);
	}

	let query_phase = open_fri_scripted(params, codeword_commitment, &round_commitments, oracle)?;

	Ok(ExtractAuthenticatedLinearRelationOpening<F> {
		final_sumcheck_value: sum,
		sampling: ExtractSamplingTrace<F> {
			challenges,
			query_indices: query_phase.query_indices.clone(),
		},
		query_phase,
		query_challenge_offset: 0,
	})
}

pub fn verify_authenticated_extract(
	params: &ExtractFriParams,
	authenticated: ExtractAuthenticatedLinearRelationOpening<F>,
) -> Result<ExtractReducedOutput<F>, ExtractError> {
	let opened_fri = verify_opened_fri_scripted(
		params,
		&authenticated.sampling.challenges,
		authenticated.query_phase,
	)?;
	Ok(ExtractReducedOutput<F> {
		final_fri_value: opened_fri.final_value,
		final_sumcheck_value: authenticated.final_sumcheck_value,
		sampling: authenticated.sampling,
	})
}

pub fn finalize_authenticated_extract(
	params: &ExtractFriParams,
	authenticated: ExtractAuthenticatedLinearRelationOpening<F>,
) -> Result<ExtractOpenedLinearRelationWithSampling<F>, ExtractError> {
	let reduced = verify_authenticated_extract(params, authenticated.clone())?;
	let query_point = crate::basefold::query_point_from_challenges(
		&authenticated.sampling.challenges[authenticated.query_challenge_offset..],
	);
	Ok(ExtractOpenedLinearRelationWithSampling<F> {
		opened: ExtractOpenedLinearRelation<F> {
			final_fri_value: reduced.final_fri_value,
			final_sumcheck_value: authenticated.final_sumcheck_value,
			query_point,
		},
		sampling: authenticated.sampling,
	})
}

fn open_fri_scripted(
	params: &ExtractFriParams,
	codeword_commitment: ExtractDigest,
	round_commitments: &[ExtractDigest],
	oracle: &mut ExtractProofOracle,
) -> Result<AuthenticatedFRIQueryPhase<F, ExtractDigest>, ExtractError> {
	let terminate_codeword_len = 1 << (params.n_final_challenges + params.log_inv_rate);
	let terminal_vector = oracle.read_merkle_vector(terminate_codeword_len)?;
	open_last_oracle_scripted(params, round_commitments, &terminal_vector)?;

	let mut layers = Vec::with_capacity(params.layer_depths.len());
	let mut layer_error = None;
	let mut i = 0;
	while i < params.layer_depths.len() {
		let layer_depth = params.layer_depths[i];
		match oracle.read_merkle_layer(1 << layer_depth) {
			Ok(layer) => layers.push(layer),
			Err(err) => layer_error = Some(err),
		}
		i += 1;
	}
	if let Some(err) = layer_error {
		return Err(err);
	}

	let mut verify_error = None;
	let mut verify_idx = 0;
	while verify_idx < layers.len() {
		if verify_error.is_none() {
			let commitment = if verify_idx == 0 {
				codeword_commitment
			} else {
				round_commitments[verify_idx - 1]
			};
			let layer = &layers[verify_idx];
			if layer.root != commitment || layer.layer_depth != params.layer_depths[verify_idx] {
				verify_error = Some(ExtractError::MerkleLayerMismatch);
			} else if layer.layer_digests.len() != (1 << params.layer_depths[verify_idx]) {
				verify_error = Some(ExtractError::IncorrectProofShape);
			}
		}
		verify_idx += 1;
	}
	if let Some(err) = verify_error {
		return Err(err);
	}

	let mut query_error = None;
	let mut opened_queries = Vec::with_capacity(params.n_test_queries);
	let mut query_indices = Vec::with_capacity(params.n_test_queries);
	let mut query_idx = 0;
	while query_idx < params.n_test_queries {
		if query_error.is_none() {
			match oracle.sample_query_index() {
				Ok(index) => {
					match read_opened_query_scripted(params, index, &layers, oracle) {
						Ok(opened_query) => {
							query_indices.push(index);
							opened_queries.push(opened_query);
						}
						Err(err) => {
							query_error = Some(err);
						}
					}
				}
				Err(err) => {
					query_error = Some(err);
				}
			}
		}
		query_idx += 1;
	}
	if let Some(err) = query_error {
		return Err(err);
	}

	let mut extracted_layers = Vec::with_capacity(layers.len());
	let mut layer_idx = 0;
	while layer_idx < layers.len() {
		extracted_layers.push(layers[layer_idx].layer_digests.clone());
		layer_idx += 1;
	}

	Ok(AuthenticatedFRIQueryPhase {
		query_indices,
		terminate_codeword: terminal_vector.data,
		layers: extracted_layers,
		opened_queries,
	})
}

fn verify_opened_fri_scripted(
	params: &ExtractFriParams,
	challenges: &[F],
	authenticated: AuthenticatedFRIQueryPhase<F, ExtractDigest>,
) -> Result<OpenedFRIQueryPhase<F, ExtractDigest>, ExtractError> {
	let interleave_challenges = &challenges[..params.log_batch_size];
	let fold_challenges = &challenges[params.log_batch_size..];
	let final_value =
		verify_last_oracle_values_scripted(params, fold_challenges, &authenticated.terminate_codeword)?;

	let mut query_error = None;
	let mut i = 0;
	while i < authenticated.opened_queries.len() {
		if query_error.is_none() {
			let result = verify_opened_query_scripted(
				params,
				interleave_challenges,
				fold_challenges,
				&authenticated.terminate_codeword,
				authenticated.opened_queries[i].clone(),
			);
			if let Err(err) = result {
				query_error = Some(err);
			}
		}
		i += 1;
	}

	if let Some(err) = query_error {
		Err(err)
	} else {
		Ok(OpenedFRIQueryPhase {
			final_value,
			query_indices: authenticated.query_indices,
			terminate_codeword: authenticated.terminate_codeword,
			layers: authenticated.layers,
		})
	}
}

fn open_last_oracle_scripted(
	params: &ExtractFriParams,
	round_commitments: &[ExtractDigest],
	terminal_vector: &ExtractMerkleVector,
) -> Result<(), ExtractError> {
	if round_commitments.is_empty() {
		return Err(ExtractError::IncorrectProofShape);
	}
	let terminal_commitment = round_commitments[round_commitments.len() - 1];
	if terminal_vector.root != terminal_commitment
		|| terminal_vector.batch_size != (1 << params.n_final_challenges)
	{
		return Err(ExtractError::MerkleVectorMismatch);
	}
	Ok(())
}

fn verify_last_oracle_values_scripted(
	params: &ExtractFriParams,
	fold_challenges: &[F],
	terminate_codeword: &[F],
) -> Result<F, ExtractError> {
	let n_prior_challenges = fold_challenges.len() - params.n_final_challenges;
	let final_challenges = &fold_challenges[n_prior_challenges..];
	let chunk_len = 1 << params.n_final_challenges;
	let repetition_count = terminate_codeword.len() / chunk_len;
	let mut repetition_codeword = Vec::with_capacity(repetition_count);

	for i in 0..repetition_count {
		let start = i * chunk_len;
		let end = start + chunk_len;
		let mut scratch_buffer = Vec::with_capacity(chunk_len);
		let mut j = start;
		while j < end {
			scratch_buffer.push(terminate_codeword[j]);
			j += 1;
		}
		repetition_codeword.push(fold_chunk_with_domain(
			&params.twiddle_evals,
			params.n_final_challenges + params.log_inv_rate,
			i,
			scratch_buffer,
			final_challenges,
		));
	}

	if repetition_codeword.is_empty() {
		return Err(ExtractError::IncorrectProofShape);
	}
	let final_value = repetition_codeword[0];
	let mut mismatch = false;
	for i in 1..repetition_codeword.len() {
		if repetition_codeword[i] != final_value {
			mismatch = true;
		}
	}

	if mismatch {
		Err(ExtractError::IncorrectDegree)
	} else {
		Ok(final_value)
	}
}

fn read_opened_query_scripted(
	params: &ExtractFriParams,
	mut index: usize,
	layers: &[ExtractMerkleLayer],
	oracle: &mut ExtractProofOracle,
) -> Result<OpenedFRIQuery<ExtractField>, ExtractError> {
	let initial_index = index;
	let first_layer_depth = params.layer_depths[0];
	let first_layer = &layers[0].layer_digests;
	let first_values = verify_coset_opening_scripted(
		oracle,
		index,
		params.log_batch_size,
		first_layer_depth,
		params.index_bits,
		first_layer,
	)?;

	let mut log_n_cosets = params.index_bits;
	let mut fold_values = Vec::with_capacity(params.fold_arities.len());
	for i in 0..params.fold_arities.len() {
		let arity = params.fold_arities[i];
		let layer = &layers[i + 1].layer_digests;
		let optimal_layer_depth = params.layer_depths[i + 1];
		let coset_index = index >> arity;
		log_n_cosets -= arity;

		let values = verify_coset_opening_scripted(
			oracle,
			coset_index,
			arity,
			optimal_layer_depth,
			log_n_cosets,
			layer,
		)?;
		fold_values.push(values);
		index = coset_index;
	}

	Ok(OpenedFRIQuery {
		initial_index,
		first_values,
		fold_values,
	})
}

fn verify_opened_query_scripted(
	params: &ExtractFriParams,
	interleave_challenges: &[F],
	fold_challenges: &[F],
	terminate_codeword: &[F],
	query: OpenedFRIQuery<ExtractField>,
) -> Result<(), ExtractError> {
	let OpenedFRIQuery {
		initial_index,
		first_values,
		fold_values,
	} = query;
	let interleave_tensor = eq_ind_partial_eval_scalars(interleave_challenges);
	let mut index = initial_index;
	let mut next_value = fold_interleaved_chunk_scalar(&first_values, &interleave_tensor);

	let mut fold_round = 0;
	let mut i = 0;
	let mut fold_error = None;
	while i < params.fold_arities.len() {
		if fold_error.is_none() {
			let arity = params.fold_arities[i];
			let values2 = fold_values[i].clone();
			let coset_index = index >> arity;
			if next_value != values2[index % (1 << arity)] {
				fold_error = Some(ExtractError::IncorrectFold {
					query_round: i,
					index,
				});
			} else {
				next_value = fold_chunk_with_domain(
					&params.twiddle_evals,
					params.index_bits - fold_round,
					coset_index,
					values2,
					&fold_challenges[fold_round..fold_round + arity],
				);
				index = coset_index;
				fold_round += arity;
			}
		}
		i += 1;
	}
	if let Some(err) = fold_error {
		return Err(err);
	}

	if next_value != terminate_codeword[index] {
		return Err(ExtractError::IncorrectFold {
			query_round: params.n_oracles() - 1,
			index,
		});
	}

	Ok(())
}

fn verify_coset_opening_scripted(
	oracle: &mut ExtractProofOracle,
	coset_index: usize,
	log_coset_size: usize,
	layer_depth: usize,
	tree_depth: usize,
	layer_digests: &[ExtractDigest],
) -> Result<Vec<ExtractField>, ExtractError> {
	let opening = oracle.read_merkle_opening(1 << log_coset_size)?;
	if opening.index != coset_index
		|| opening.layer_depth != layer_depth
		|| opening.tree_depth != tree_depth
		|| opening.layer_digests != layer_digests
	{
		return Err(ExtractError::MerkleOpeningMismatch);
	}
	Ok(opening.values)
}

fn calculate_fri_commit_rounds(
	log_batch_size: usize,
	fold_arities: &[usize],
	n_rounds: usize,
) -> Vec<bool> {
	let mut commit_rounds = Vec::with_capacity(fold_arities.len() + 1);
	let mut round_idx = log_batch_size;
	if round_idx < n_rounds {
		commit_rounds.push(round_idx);
	}

	let mut i = 0;
	while i < fold_arities.len() {
		let arity = fold_arities[i];
		round_idx += arity;
		if round_idx < n_rounds {
			commit_rounds.push(round_idx);
		}
		i += 1;
	}

	let mut result = Vec::with_capacity(n_rounds);
	let mut next_commit = 0;
	let mut round = 0;
	while round < n_rounds {
		let is_commit = next_commit < commit_rounds.len() && commit_rounds[next_commit] == round;
		result.push(is_commit);
		if is_commit {
			next_commit += 1;
		}
		round += 1;
	}

	result
}

fn recover_round_coeffs(sum: F, coeffs: [F; 2]) -> [F; 3] {
	let coeff_0 = coeffs[0];
	let coeff_1 = coeffs[1];
	let coeff_2 = sum - coeff_0 - coeff_0 - coeff_1;
	[coeff_0, coeff_1, coeff_2]
}

fn evaluate_round_coeffs(coeffs: [F; 3], x: F) -> F {
	let coeff_0 = coeffs[0];
	let coeff_1 = coeffs[1];
	let coeff_2 = coeffs[2];
	coeff_0 + x * (coeff_1 + x * coeff_2)
}

fn eq_ind_partial_eval_scalars(point: &[F]) -> Vec<ExtractField> {
	let mut result = Vec::with_capacity(1);
	result.push(F::ONE);
	let mut i = 0;
	while i < point.len() {
		let r_i = point[i];
		let len = result.len();
		let mut next = Vec::with_capacity(len * 2);
		let mut prods = Vec::with_capacity(len);
		let mut j = 0;
		while j < len {
			let value = result[j];
			let prod = value * r_i;
			next.push(value - prod);
			prods.push(prod);
			j += 1;
		}
		let mut j = 0;
		while j < prods.len() {
			next.push(prods[j]);
			j += 1;
		}
		result = next;
		i += 1;
	}

	result
}

fn fold_pair_with_domain(
	twiddle_evals: &[Vec<ExtractField>],
	round: usize,
	index: usize,
	values: (F, F),
	challenge: F,
) -> F {
	let basis_row = &twiddle_evals[twiddle_evals.len() - round][1..];
	let mut twiddle = F::ZERO;
	let mut mask = index;
	let mut i = 0;
	while mask != 0 {
		if mask & 1 == 1 {
			twiddle = twiddle + basis_row[i];
		}
		mask >>= 1;
		i += 1;
	}
	let mut left = values.0;
	let mut right = values.1;
	right = right + left;
	left = left + right * twiddle;
	left + (right - left) * challenge
}

fn fold_chunk_with_domain(
	twiddle_evals: &[Vec<ExtractField>],
	mut log_len: usize,
	chunk_index: usize,
	mut values: Vec<ExtractField>,
	challenges: &[F],
) -> F {
	let mut log_size = challenges.len();
	let mut challenge_idx = 0;
	while challenge_idx < challenges.len() {
		let challenge = challenges[challenge_idx];
		let half = 1 << (log_size - 1);
		let mut next_values = Vec::with_capacity(half);
		let mut index_offset = 0;
		while index_offset < half {
			let pair = (values[index_offset << 1], values[(index_offset << 1) | 1]);
			next_values.push(fold_pair_with_domain(
				twiddle_evals,
				log_len,
				(chunk_index << (log_size - 1)) | index_offset,
				pair,
				challenge,
			));
			index_offset += 1;
		}
		values = next_values;
		log_len -= 1;
		log_size -= 1;
		challenge_idx += 1;
	}

	values[0]
}

fn fold_interleaved_chunk_scalar(values: &[F], tensor: &[F]) -> F {
	let mut acc = F::ZERO;
	for i in 0..values.len() {
		acc = acc + values[i] * tensor[i];
	}
	acc
}
