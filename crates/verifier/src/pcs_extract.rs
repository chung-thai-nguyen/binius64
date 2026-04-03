// Copyright 2026 The Binius Developers

//! Extraction-oriented replay verifier for the RingSwitch + BaseFold / FRI slice.
//!
//! This module composes the plain-data RingSwitch replay verifier with the plain-data BaseFold /
//! FRI replay verifier and checks the same final transparent-polynomial consistency condition as
//! the upstream verifier channel.

use binius_iop::basefold_extract::F;
use binius_iop::basefold_extract;
use binius_iop::protocol_boundary::{
	AuthenticatedStatementTranscriptProtocol, StatementTranscriptProtocol,
};

use crate::ring_switch_extract::{
	ExtractRingSwitchChannel<F>, ExtractRingSwitchEqRelation<F>, ExtractRingSwitchStatement<F>,
	ExtractRingSwitchTranscriptView<F>, eval_relation_extract,
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
pub struct ExtractPcsStatement<F: ExtractField> {
	pub params: basefold_extract::ExtractFriParams,
	pub codeword_commitment: ExtractDigest,
	pub witness_eval: F,
	pub eval_point: Vec<ExtractField>,
}

/// Monomorphic PCS transcript view exported to Hax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractPcsTranscriptView<F: ExtractField> {
	pub ring_switch: ExtractRingSwitchTranscriptView<F>,
	pub basefold: basefold_extract::ExtractBasefoldTranscriptView<F>,
}

/// Thin protocol-boundary marker for the extraction-oriented PCS verifier.
pub struct ExtractPcsProtocol<F: ExtractField>;

/// Monomorphic typed PCS-opening output exported to Hax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractPcsOpeningOutput<F: ExtractField> {
	pub relation: ExtractRingSwitchEqRelation<F>,
	pub sumcheck_claim: F,
	pub opened: basefold_extract::ExtractOpenedLinearRelation<F>,
	pub sampling: basefold_extract::ExtractSamplingTrace<F>,
	pub transparent_eval: F,
}

/// Monomorphic authenticated PCS opening after transcript / Merkle checks but before the final
/// pure IOP semantic finalization step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractAuthenticatedPcsOpening<F: ExtractField> {
	pub relation: ExtractRingSwitchEqRelation<F>,
	pub sumcheck_claim: F,
	pub opening: basefold_extract::ExtractAuthenticatedLinearRelationOpening<F>,
}

impl<F: ExtractField> ExtractPcsStatement<F> {
	pub fn verify_transcript(
		&self,
		transcript: &ExtractPcsTranscriptView<F>,
	) -> Result<ExtractPcsOpeningOutput<F>, ExtractError> {
		ExtractPcsProtocol<F>::verify_statement_transcript(self, transcript)
	}

	pub fn verify_authenticated_transcript(
		&self,
		transcript: &ExtractPcsTranscriptView<F>,
	) -> Result<ExtractAuthenticatedPcsOpening<F>, ExtractError> {
		ExtractPcsProtocol<F>::verify_authenticated_statement_transcript(self, transcript)
	}

	pub fn verify_authenticated(
		&self,
		authenticated: ExtractAuthenticatedPcsOpening<F>,
	) -> Result<ExtractPcsOpeningOutput<F>, ExtractError> {
		ExtractPcsProtocol<F>::verify_authenticated(self, authenticated)
	}
}

impl AuthenticatedStatementTranscriptProtocol for ExtractPcsProtocol<F> {
	type Statement = ExtractPcsStatement<F>;
	type TranscriptView = ExtractPcsTranscriptView<F>;
	type Authenticated = ExtractAuthenticatedPcsOpening<F>;
	type Output = ExtractPcsOpeningOutput<F>;
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

impl From<crate::pcs::PcsOpeningOutput<F, ring_switch::RingSwitchEqRelation<ExtractField>>>
	for ExtractPcsOpeningOutput<F>
{
	fn from(
		value: crate::pcs::PcsOpeningOutput<
			F,
			ring_switch::RingSwitchEqRelation<ExtractField>,
		>,
	) -> Self {
		Self {
			relation: value.relation.into(),
			sumcheck_claim: value.sumcheck_claim,
			opened: basefold_extract::ExtractOpenedLinearRelation<F> {
				final_fri_value: value.opened.final_fri_value,
				final_sumcheck_value: value.opened.final_sumcheck_value,
				query_point: value.opened.query_point,
			},
			sampling: basefold_extract::ExtractSamplingTrace<F> {
				challenges: value.sampling.challenges,
				query_indices: value.sampling.query_indices,
			},
			transparent_eval: value.transparent_eval,
		}
	}
}

pub fn verify_scripted_extract(
	params: &basefold_extract::ExtractFriParams,
	codeword_commitment: ExtractDigest,
	witness_eval: F,
	eval_point: &[F],
	ring_switch_channel: &mut ExtractRingSwitchChannel<F>,
	basefold_oracle: &mut basefold_extract::ExtractProofOracle,
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

pub fn verify_authenticated_scripted_extract(
	params: &basefold_extract::ExtractFriParams,
	codeword_commitment: ExtractDigest,
	witness_eval: F,
	eval_point: &[F],
	ring_switch_channel: &mut ExtractRingSwitchChannel<F>,
	basefold_oracle: &mut basefold_extract::ExtractProofOracle,
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

	Ok(ExtractAuthenticatedPcsOpening<F> {
		relation: ring_switch_output.relation,
		sumcheck_claim: ring_switch_output.sumcheck_claim,
		opening,
	})
}

pub fn finalize_authenticated_extract(
	params: &basefold_extract::ExtractFriParams,
	authenticated: ExtractAuthenticatedPcsOpening<F>,
) -> Result<ExtractPcsOpeningOutput<F>, ExtractError> {
	let basefold_extract::ExtractOpenedLinearRelationWithSampling<F> { opened, sampling } =
		basefold_extract::finalize_authenticated_extract(params, authenticated.opening)
			.map_err(|_| ExtractError::BaseFoldFailure)?;
	let transparent_eval =
		eval_relation_extract(&authenticated.relation, &opened.query_point);
	let final_consistency_error =
		opened.final_sumcheck_value - opened.final_fri_value * transparent_eval;
	if final_consistency_error != F::ZERO {
		return Err(ExtractError::InvalidFinalConsistency);
	}

	Ok(ExtractPcsOpeningOutput<F> {
		relation: authenticated.relation,
		sumcheck_claim: authenticated.sumcheck_claim,
		opened,
		sampling,
		transparent_eval,
	})
}

pub fn verify_statement_transcript_extract(
	statement: &ExtractPcsStatement<F>,
	transcript: &ExtractPcsTranscriptView<F>,
) -> Result<ExtractPcsOpeningOutput<F>, ExtractError> {
	let authenticated =
		verify_authenticated_statement_transcript_extract(statement, transcript)?;
	finalize_authenticated_extract(&statement.params, authenticated)
}

pub fn verify_authenticated_statement_transcript_extract(
	statement: &ExtractPcsStatement<F>,
	transcript: &ExtractPcsTranscriptView<F>,
) -> Result<ExtractAuthenticatedPcsOpening<F>, ExtractError> {
	let ring_switch_statement = ExtractRingSwitchStatement<F> {
		witness_eval: statement.witness_eval,
		eval_point: statement.eval_point.clone(),
	};
	let ring_switch_output = verify_ring_switch_statement_transcript_extract(
		&ring_switch_statement,
		&transcript.ring_switch,
	)
	.map_err(|_| ExtractError::RingSwitchFailure)?;

	let basefold_statement = basefold_extract::ExtractBasefoldStatement<F> {
		params: statement.params.clone(),
		codeword_commitment: statement.codeword_commitment,
		evaluation_claim: ring_switch_output.sumcheck_claim,
	};
	let opening = basefold_extract::verify_authenticated_statement_transcript_extract(
		&basefold_statement,
		&transcript.basefold,
	)
	.map_err(|_| ExtractError::BaseFoldFailure)?;

	Ok(ExtractAuthenticatedPcsOpening<F> {
		relation: ring_switch_output.relation,
		sumcheck_claim: ring_switch_output.sumcheck_claim,
		opening,
	})
}
