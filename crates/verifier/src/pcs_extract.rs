// Copyright 2026 The Binius Developers

//! Extraction-oriented replay verifier for the RingSwitch + BaseFold / FRI slice.
//!
//! This module composes the plain-data RingSwitch replay verifier with the plain-data BaseFold /
//! FRI replay verifier and checks the same final transparent-polynomial consistency condition as
//! the upstream verifier channel.

use binius_iop::basefold_extract::{self, ExtractField};
use binius_iop::protocol_boundary::AuthenticatedStatementTranscriptProtocol;
use binius_field::BinaryField128bGhash;

use crate::ring_switch_extract::{
	ExtractRingSwitchChannel, ExtractRingSwitchEqRelation, ExtractRingSwitchStatement,
	ExtractRingSwitchTranscriptView, eval_relation_extract,
	verify_statement_transcript_extract as verify_ring_switch_statement_transcript_extract,
	verify_scripted_extract as verify_ring_switch_scripted_extract,
};
use crate::ring_switch;

pub type ExtractDigest = basefold_extract::ExtractDigest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
	RingSwitchFailure,
	BaseFoldFailure,
	InvalidFinalConsistency,
}

/// Monomorphic PCS statement exported to Hax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractPcsStatement<F: ExtractField = BinaryField128bGhash> {
	pub params: basefold_extract::ExtractFriParams<F>,
	pub codeword_commitment: ExtractDigest,
	pub witness_eval: F,
	pub eval_point: Vec<F>,
}

/// Monomorphic PCS transcript view exported to Hax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractPcsTranscriptView<F: ExtractField = BinaryField128bGhash> {
	pub ring_switch: ExtractRingSwitchTranscriptView<F>,
	pub basefold: basefold_extract::ExtractBasefoldTranscriptView<F>,
}

/// Thin protocol-boundary marker for the extraction-oriented PCS verifier.
pub struct ExtractPcsProtocol;

/// Monomorphic typed PCS-opening output exported to Hax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractPcsOpeningOutput<F: ExtractField = BinaryField128bGhash> {
	pub relation: ExtractRingSwitchEqRelation<F>,
	pub sumcheck_claim: F,
	pub opened: basefold_extract::ExtractOpenedLinearRelation<F>,
	pub sampling: basefold_extract::ExtractSamplingTrace<F>,
	pub transparent_eval: F,
}

/// Monomorphic authenticated PCS opening after transcript / Merkle checks but before the final
/// pure IOP semantic finalization step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractAuthenticatedPcsOpening<F: ExtractField = BinaryField128bGhash> {
	pub relation: ExtractRingSwitchEqRelation<F>,
	pub sumcheck_claim: F,
	pub opening: basefold_extract::ExtractAuthenticatedLinearRelationOpening<F>,
}

impl<F: ExtractField> ExtractPcsStatement<F> {
	pub fn verify_transcript(
		&self,
		transcript: &ExtractPcsTranscriptView<F>,
	) -> Result<ExtractPcsOpeningOutput<F>, ExtractError> {
		verify_statement_transcript_extract(self, transcript)
	}

	pub fn verify_authenticated_transcript(
		&self,
		transcript: &ExtractPcsTranscriptView<F>,
	) -> Result<ExtractAuthenticatedPcsOpening<F>, ExtractError> {
		verify_authenticated_statement_transcript_extract(self, transcript)
	}

	pub fn verify_authenticated(
		&self,
		authenticated: ExtractAuthenticatedPcsOpening<F>,
	) -> Result<ExtractPcsOpeningOutput<F>, ExtractError> {
		finalize_authenticated_extract(&self.params, authenticated)
	}
}

impl AuthenticatedStatementTranscriptProtocol for ExtractPcsProtocol {
	type Statement = ExtractPcsStatement<BinaryField128bGhash>;
	type TranscriptView = ExtractPcsTranscriptView<BinaryField128bGhash>;
	type Authenticated = ExtractAuthenticatedPcsOpening<BinaryField128bGhash>;
	type Output = ExtractPcsOpeningOutput<BinaryField128bGhash>;
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
		finalize_authenticated_extract(&statement.params, authenticated)
	}
}

impl<F> From<crate::pcs::PcsOpeningOutput<F, ring_switch::RingSwitchEqRelation<F>>>
	for ExtractPcsOpeningOutput<F>
where
	F: ExtractField + binius_field::BinaryField + binius_field::PackedField<Scalar = F>,
{
	fn from(
		value: crate::pcs::PcsOpeningOutput<
			F,
			ring_switch::RingSwitchEqRelation<F>,
		>,
	) -> Self {
		Self {
			relation: value.relation.into(),
			sumcheck_claim: value.sumcheck_claim,
			opened: basefold_extract::ExtractOpenedLinearRelation {
				final_fri_value: value.opened.final_fri_value,
				final_sumcheck_value: value.opened.final_sumcheck_value,
				query_point: value.opened.query_point,
			},
			sampling: basefold_extract::ExtractSamplingTrace {
				challenges: value.sampling.challenges,
				query_indices: value.sampling.query_indices,
			},
			transparent_eval: value.transparent_eval,
		}
	}
}

pub fn verify_scripted_extract<F: ExtractField>(
	params: &basefold_extract::ExtractFriParams<F>,
	codeword_commitment: ExtractDigest,
	witness_eval: F,
	eval_point: &[F],
	ring_switch_channel: &mut ExtractRingSwitchChannel<F>,
	basefold_oracle: &mut basefold_extract::ExtractProofOracle<F>,
) -> Result<ExtractPcsOpeningOutput<F>, ExtractError> {
	let authenticated = verify_authenticated_scripted_extract(
		params,
		codeword_commitment,
		witness_eval,
		eval_point,
		ring_switch_channel,
		basefold_oracle,
	)?;
	finalize_authenticated_extract(params, authenticated)
}

pub fn verify_authenticated_scripted_extract<F: ExtractField>(
	params: &basefold_extract::ExtractFriParams<F>,
	codeword_commitment: ExtractDigest,
	witness_eval: F,
	eval_point: &[F],
	ring_switch_channel: &mut ExtractRingSwitchChannel<F>,
	basefold_oracle: &mut basefold_extract::ExtractProofOracle<F>,
) -> Result<ExtractAuthenticatedPcsOpening<F>, ExtractError> {
	let ring_switch_output = verify_ring_switch_scripted_extract(
		witness_eval,
		eval_point,
		ring_switch_channel,
	)
	.map_err(|_| ExtractError::RingSwitchFailure)?;

	let opening = basefold_extract::open_authenticated_extract(
		params,
		codeword_commitment,
		ring_switch_output.sumcheck_claim,
		basefold_oracle,
	)
	.map_err(|_| ExtractError::BaseFoldFailure)?;

	Ok(ExtractAuthenticatedPcsOpening {
		relation: ring_switch_output.relation,
		sumcheck_claim: ring_switch_output.sumcheck_claim,
		opening,
	})
}

pub fn finalize_authenticated_extract<F: ExtractField>(
	params: &basefold_extract::ExtractFriParams<F>,
	authenticated: ExtractAuthenticatedPcsOpening<F>,
) -> Result<ExtractPcsOpeningOutput<F>, ExtractError> {
	let basefold_extract::ExtractOpenedLinearRelationWithSampling { opened, sampling } =
		basefold_extract::finalize_authenticated_extract(params, authenticated.opening)
			.map_err(|_| ExtractError::BaseFoldFailure)?;
	let transparent_eval =
		eval_relation_extract(&authenticated.relation, &opened.query_point);
	let final_consistency_error =
		opened.final_sumcheck_value.sub(opened.final_fri_value.mul(transparent_eval));
	if final_consistency_error != F::zero() {
		return Err(ExtractError::InvalidFinalConsistency);
	}

	Ok(ExtractPcsOpeningOutput {
		relation: authenticated.relation,
		sumcheck_claim: authenticated.sumcheck_claim,
		opened,
		sampling,
		transparent_eval,
	})
}

pub fn verify_statement_transcript_extract<F: ExtractField>(
	statement: &ExtractPcsStatement<F>,
	transcript: &ExtractPcsTranscriptView<F>,
) -> Result<ExtractPcsOpeningOutput<F>, ExtractError> {
	let authenticated =
		verify_authenticated_statement_transcript_extract(statement, transcript)?;
	finalize_authenticated_extract(&statement.params, authenticated)
}

pub fn verify_authenticated_statement_transcript_extract<F: ExtractField>(
	statement: &ExtractPcsStatement<F>,
	transcript: &ExtractPcsTranscriptView<F>,
) -> Result<ExtractAuthenticatedPcsOpening<F>, ExtractError> {
	let ring_switch_statement = ExtractRingSwitchStatement {
		witness_eval: statement.witness_eval,
		eval_point: statement.eval_point.clone(),
	};
	let ring_switch_output = verify_ring_switch_statement_transcript_extract(
		&ring_switch_statement,
		&transcript.ring_switch,
	)
	.map_err(|_| ExtractError::RingSwitchFailure)?;

	let basefold_statement = basefold_extract::ExtractBasefoldStatement {
		params: statement.params.clone(),
		codeword_commitment: statement.codeword_commitment,
		evaluation_claim: ring_switch_output.sumcheck_claim,
	};
	let opening = basefold_extract::verify_authenticated_statement_transcript_extract(
		&basefold_statement,
		&transcript.basefold,
	)
	.map_err(|_| ExtractError::BaseFoldFailure)?;

	Ok(ExtractAuthenticatedPcsOpening {
		relation: ring_switch_output.relation,
		sumcheck_claim: ring_switch_output.sumcheck_claim,
		opening,
	})
}

pub fn verify_statement_transcript_128b_ghash_extract(
	statement: &ExtractPcsStatement<BinaryField128bGhash>,
	transcript: &ExtractPcsTranscriptView<BinaryField128bGhash>,
) -> Result<ExtractPcsOpeningOutput<BinaryField128bGhash>, ExtractError> {
	verify_statement_transcript_extract(statement, transcript)
}

pub fn verify_authenticated_statement_transcript_128b_ghash_extract(
	statement: &ExtractPcsStatement<BinaryField128bGhash>,
	transcript: &ExtractPcsTranscriptView<BinaryField128bGhash>,
) -> Result<ExtractAuthenticatedPcsOpening<BinaryField128bGhash>, ExtractError> {
	verify_authenticated_statement_transcript_extract(statement, transcript)
}

pub fn finalize_authenticated_128b_ghash_extract(
	params: &basefold_extract::ExtractFriParams<BinaryField128bGhash>,
	authenticated: ExtractAuthenticatedPcsOpening<BinaryField128bGhash>,
) -> Result<ExtractPcsOpeningOutput<BinaryField128bGhash>, ExtractError> {
	finalize_authenticated_extract(params, authenticated)
}

/// Hax-oriented aliases matching the FRI-Binius-FV bridge `IOPCoreTransportSplit` naming:
/// **crypto transport** (Layer 1) vs **IOP semantic finalization** (Layer 2) for composed PCS.
///
/// After `cargo hax … lean`, these share definitions with the legacy names so generated Lean
/// stays identical unless new `+…` extraction items opt into the aliases.
pub mod layered {
	pub use super::{
		ExtractAuthenticatedPcsOpening as PcsCryptoTransportOutput,
		ExtractPcsOpeningOutput as PcsIopSemanticOutput,
		finalize_authenticated_128b_ghash_extract as iop_core_finalize_pcs_128b_ghash_extract,
		verify_authenticated_statement_transcript_128b_ghash_extract as crypto_transport_verify_pcs_128b_ghash_extract,
		verify_statement_transcript_128b_ghash_extract as verify_pcs_full_128b_ghash_extract,
	};
}
