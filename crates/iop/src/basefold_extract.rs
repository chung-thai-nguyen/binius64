// Copyright 2026 The Binius Developers

//! Extraction-oriented scripted BaseFold verifier.
//!
//! This module provides a monomorphic, plain-data replay of the BaseFold / FRI verifier slice.
//! It is intended for extraction experiments where the live verifier's transcript, Merkle scheme,
//! and generic field interfaces are too rich for current extraction tools.

use binius_field::BinaryField128bGhash;

use crate::basefold::ReducedOutput;

pub type ExtractField = BinaryField128bGhash;
pub type ExtractDigest = [u8; 32];

#[derive(Debug, Clone)]
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
	MerkleVectorMismatch,
	MerkleOpeningMismatch,
	MerkleLayerMismatch,
	IncorrectFold { query_round: usize, index: usize },
	IncorrectDegree,
}

#[derive(Debug, Clone)]
pub struct ExtractMerkleVector {
	pub root: ExtractDigest,
	pub data: Vec<ExtractField>,
	pub batch_size: usize,
}

#[derive(Debug, Clone)]
pub struct ExtractMerkleOpening {
	pub index: usize,
	pub values: Vec<ExtractField>,
	pub layer_depth: usize,
	pub tree_depth: usize,
	pub layer_digests: Vec<ExtractDigest>,
}

#[derive(Debug, Clone)]
pub struct ExtractMerkleLayer {
	pub root: ExtractDigest,
	pub layer_depth: usize,
	pub layer_digests: Vec<ExtractDigest>,
}

#[derive(Debug, Clone, Default)]
pub struct ExtractProofOracle {
	pub round_coeffs: Vec<[ExtractField; 2]>,
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
	pub fn read_round_coeffs(&mut self) -> Result<[ExtractField; 2], ExtractError> {
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

	pub fn sample_challenge(&mut self) -> Result<ExtractField, ExtractError> {
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

	pub fn verify_merkle_vector(
		&mut self,
		root: ExtractDigest,
		data: &[ExtractField],
		batch_size: usize,
	) -> Result<(), ExtractError> {
		if let Some(expected) = self.merkle_vectors.get(self.merkle_vectors_pos) {
			self.merkle_vectors_pos += 1;
			if expected.root == root && expected.data == data && expected.batch_size == batch_size {
				Ok(())
			} else {
				Err(ExtractError::MerkleVectorMismatch)
			}
		} else {
			Err(ExtractError::MissingObject)
		}
	}

	pub fn verify_merkle_opening(
		&mut self,
		index: usize,
		values: &[ExtractField],
		layer_depth: usize,
		tree_depth: usize,
		layer_digests: &[ExtractDigest],
	) -> Result<(), ExtractError> {
		if let Some(expected) = self.merkle_openings.get(self.merkle_openings_pos) {
			self.merkle_openings_pos += 1;
			if expected.index == index
				&& expected.values == values
				&& expected.layer_depth == layer_depth
				&& expected.tree_depth == tree_depth
				&& expected.layer_digests == layer_digests
			{
				Ok(())
			} else {
				Err(ExtractError::MerkleOpeningMismatch)
			}
		} else {
			Err(ExtractError::MissingObject)
		}
	}

	pub fn verify_merkle_layer(
		&mut self,
		root: ExtractDigest,
		layer_depth: usize,
		layer_digests: &[ExtractDigest],
	) -> Result<(), ExtractError> {
		if let Some(expected) = self.merkle_layers.get(self.merkle_layers_pos) {
			self.merkle_layers_pos += 1;
			if expected.root == root
				&& expected.layer_depth == layer_depth
				&& expected.layer_digests == layer_digests
			{
				Ok(())
			} else {
				Err(ExtractError::MerkleLayerMismatch)
			}
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

pub fn verify_scripted_128b_ghash_extract(
	params: &ExtractFriParams,
	codeword_commitment: ExtractDigest,
	evaluation_claim: ExtractField,
	oracle: &mut ExtractProofOracle,
) -> Result<ReducedOutput<ExtractField>, ExtractError> {
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

	let final_fri_value =
		verify_fri_scripted(params, codeword_commitment, &round_commitments, &challenges, oracle)?;

	Ok(ReducedOutput {
		final_fri_value,
		final_sumcheck_value: sum,
		challenges,
	})
}

fn verify_fri_scripted(
	params: &ExtractFriParams,
	codeword_commitment: ExtractDigest,
	round_commitments: &[ExtractDigest],
	challenges: &[ExtractField],
	oracle: &mut ExtractProofOracle,
) -> Result<ExtractField, ExtractError> {
	let interleave_challenges = &challenges[..params.log_batch_size];
	let fold_challenges = &challenges[params.log_batch_size..];
	let terminate_codeword_len = 1 << (params.n_final_challenges + params.log_inv_rate);
	let terminate_codeword = oracle.read_decommitment_scalars(terminate_codeword_len)?;
	let final_value = verify_last_oracle_scripted(
		params,
		round_commitments,
		fold_challenges,
		&terminate_codeword,
		oracle,
	)?;

	let mut layers = Vec::with_capacity(params.layer_depths.len());
	let mut layer_error = None;
	let mut i = 0;
	while i < params.layer_depths.len() {
		let layer_depth = params.layer_depths[i];
		match oracle.read_commitment_vec(1 << layer_depth) {
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
			if let Err(err) = oracle.verify_merkle_layer(
				commitment,
				params.layer_depths[verify_idx],
				&layers[verify_idx],
			) {
				verify_error = Some(err);
			}
		}
		verify_idx += 1;
	}
	if let Some(err) = verify_error {
		return Err(err);
	}

	let mut query_error = None;
	let mut query_idx = 0;
	while query_idx < params.n_test_queries {
		if query_error.is_none() {
			match oracle.sample_query_index() {
				Ok(index) => {
					let result = verify_query_scripted(
						params,
						interleave_challenges,
						fold_challenges,
						index,
						&terminate_codeword,
						&layers,
						oracle,
					);
					if let Err(err) = result {
						query_error = Some(err);
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
		Err(err)
	} else {
		Ok(final_value)
	}
}

fn verify_last_oracle_scripted(
	params: &ExtractFriParams,
	round_commitments: &[ExtractDigest],
	fold_challenges: &[ExtractField],
	terminate_codeword: &[ExtractField],
	oracle: &mut ExtractProofOracle,
) -> Result<ExtractField, ExtractError> {
	if round_commitments.is_empty() {
		return Err(ExtractError::IncorrectProofShape);
	}
	let terminal_commitment = round_commitments[round_commitments.len() - 1];
	oracle.verify_merkle_vector(
		terminal_commitment,
		terminate_codeword,
		1 << params.n_final_challenges,
	)?;

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

fn verify_query_scripted(
	params: &ExtractFriParams,
	interleave_challenges: &[ExtractField],
	fold_challenges: &[ExtractField],
	mut index: usize,
	terminate_codeword: &[ExtractField],
	layers: &[Vec<ExtractDigest>],
	oracle: &mut ExtractProofOracle,
) -> Result<(), ExtractError> {
	let interleave_tensor = eq_ind_partial_eval_scalars(interleave_challenges);
	let first_layer_depth = params.layer_depths[0];
	let first_layer = &layers[0];
	let values = verify_coset_opening_scripted(
		oracle,
		index,
		params.log_batch_size,
		first_layer_depth,
		params.index_bits,
		first_layer,
	)?;
	let mut next_value = fold_interleaved_chunk_scalar(&values, &interleave_tensor);

	let mut fold_round = 0;
	let mut log_n_cosets = params.index_bits;
	let mut fold_error = None;

	for i in 0..params.fold_arities.len() {
		if fold_error.is_none() {
			let arity = params.fold_arities[i];
			let layer = &layers[i + 1];
			let optimal_layer_depth = params.layer_depths[i + 1];
			let coset_index = index >> arity;
			log_n_cosets -= arity;

			let values_result = verify_coset_opening_scripted(
				oracle,
				coset_index,
				arity,
				optimal_layer_depth,
				log_n_cosets,
				layer,
			);
			match values_result {
				Ok(values2) => {
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
				Err(err) => {
					fold_error = Some(err);
				}
			}
		}
	}

	if let Some(err) = fold_error {
		return Err(err);
	}

	if next_value != terminate_codeword[index] {
		Err(ExtractError::IncorrectFold {
			query_round: params.n_oracles() - 1,
			index,
		})
	} else {
		Ok(())
	}
}

fn verify_coset_opening_scripted(
	oracle: &mut ExtractProofOracle,
	coset_index: usize,
	log_coset_size: usize,
	layer_depth: usize,
	tree_depth: usize,
	layer_digests: &[ExtractDigest],
) -> Result<Vec<ExtractField>, ExtractError> {
	let values = oracle.read_decommitment_scalars(1 << log_coset_size)?;
	oracle.verify_merkle_opening(coset_index, &values, layer_depth, tree_depth, layer_digests)?;
	Ok(values)
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

fn recover_round_coeffs(sum: ExtractField, coeffs: [ExtractField; 2]) -> [ExtractField; 3] {
	let coeff_0 = coeffs[0];
	let coeff_1 = coeffs[1];
	let coeff_2 = sum - coeff_0 - coeff_0 - coeff_1;
	[coeff_0, coeff_1, coeff_2]
}

fn evaluate_round_coeffs(coeffs: [ExtractField; 3], x: ExtractField) -> ExtractField {
	let coeff_0 = coeffs[0];
	let coeff_1 = coeffs[1];
	let coeff_2 = coeffs[2];
	coeff_0 + x * (coeff_1 + x * coeff_2)
}

fn eq_ind_partial_eval_scalars(point: &[ExtractField]) -> Vec<ExtractField> {
	let mut result = Vec::with_capacity(1);
	result.push(ExtractField::new(1));
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
	values: (ExtractField, ExtractField),
	challenge: ExtractField,
) -> ExtractField {
	let basis_row = &twiddle_evals[twiddle_evals.len() - round][1..];
	let mut twiddle = ExtractField::new(0);
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
	challenges: &[ExtractField],
) -> ExtractField {
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

fn fold_interleaved_chunk_scalar(values: &[ExtractField], tensor: &[ExtractField]) -> ExtractField {
	let mut acc = ExtractField::new(0);
	for i in 0..values.len() {
		acc = acc + values[i] * tensor[i];
	}
	acc
}
