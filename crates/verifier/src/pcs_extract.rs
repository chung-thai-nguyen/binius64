// Copyright 2026 The Binius Developers

//! Extraction-oriented replay verifier for the RingSwitch + BaseFold / FRI slice.
//!
//! This module composes the plain-data RingSwitch replay verifier with the plain-data BaseFold /
//! FRI replay verifier and checks the same final transparent-polynomial consistency condition as
//! the upstream verifier channel.

use binius_field::BinaryField128bGhash;
use binius_iop::basefold_extract;

use crate::ring_switch_extract::{
	ExtractRingSwitchChannel, eval_rs_eq_128b_ghash_extract,
	verify_scripted_128b_ghash_extract as verify_ring_switch_scripted_128b_ghash_extract,
};

pub type ExtractField = BinaryField128bGhash;
pub type ExtractDigest = basefold_extract::ExtractDigest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
	RingSwitchFailure,
	BaseFoldFailure,
	InvalidFinalConsistency,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractPcsOpeningOutput {
	pub eq_r_double_prime: Vec<ExtractField>,
	pub sumcheck_claim: ExtractField,
	pub final_fri_value: ExtractField,
	pub final_sumcheck_value: ExtractField,
	pub challenges: Vec<ExtractField>,
	pub transparent_eval: ExtractField,
}

pub fn verify_scripted_128b_ghash_extract(
	params: &basefold_extract::ExtractFriParams,
	codeword_commitment: ExtractDigest,
	witness_eval: ExtractField,
	eval_point: &[ExtractField],
	ring_switch_channel: &mut ExtractRingSwitchChannel,
	basefold_oracle: &mut basefold_extract::ExtractProofOracle,
) -> Result<ExtractPcsOpeningOutput, ExtractError> {
	let ring_switch_output = verify_ring_switch_scripted_128b_ghash_extract(
		witness_eval,
		eval_point,
		ring_switch_channel,
	)
	.map_err(|_| ExtractError::RingSwitchFailure)?;

	let basefold_output = basefold_extract::verify_scripted_128b_ghash_extract(
		params,
		codeword_commitment,
		ring_switch_output.sumcheck_claim,
		basefold_oracle,
	)
	.map_err(|_| ExtractError::BaseFoldFailure)?;

	let mut query_point = Vec::with_capacity(basefold_output.challenges.len());
	let mut i = basefold_output.challenges.len();
	while i > 0 {
		i -= 1;
		query_point.push(basefold_output.challenges[i]);
	}

	let transparent_eval = eval_rs_eq_128b_ghash_extract(
		&eval_point[crate::ring_switch_extract::LOG_PACKING..],
		&query_point,
		&ring_switch_output.eq_r_double_prime,
	);

	if basefold_output.final_sumcheck_value != basefold_output.final_fri_value * transparent_eval {
		return Err(ExtractError::InvalidFinalConsistency);
	}

	Ok(ExtractPcsOpeningOutput {
		eq_r_double_prime: ring_switch_output.eq_r_double_prime,
		sumcheck_claim: ring_switch_output.sumcheck_claim,
		final_fri_value: basefold_output.final_fri_value,
		final_sumcheck_value: basefold_output.final_sumcheck_value,
		challenges: basefold_output.challenges,
		transparent_eval,
	})
}
