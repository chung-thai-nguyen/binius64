// Copyright 2026 The Binius Developers

//! Shared typed PCS-opening outputs.
//!
//! This module defines the semantic output object shared by the native transcript-backed Binius
//! verifier path and the extraction-oriented replay verifier path.

use binius_field::Field;
use binius_iop::basefold;

use crate::ring_switch;

/// Plain-data ring-switch relation packaged at the PCS boundary.
///
/// This is intentionally transport-agnostic and replay-agnostic: both the transcript-backed
/// native verifier and the extraction-oriented replay verifier normalize into this representation
/// before exposing the final PCS-opening output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingSwitchEqRelation<F> {
	pub eval_point_high: Vec<F>,
	pub eq_r_double_prime: Vec<F>,
}

impl<F> From<ring_switch::RingSwitchEqRelation<F>> for RingSwitchEqRelation<F>
where
	F: binius_field::BinaryField + binius_field::PackedField<Scalar = F>,
{
	fn from(value: ring_switch::RingSwitchEqRelation<F>) -> Self {
		Self {
			eval_point_high: value.eval_point_high,
			eq_r_double_prime: value.eq_r_double_prime,
		}
	}
}

impl<F> RingSwitchEqRelation<F>
where
	F: binius_field::BinaryField + binius_field::PackedField<Scalar = F>,
{
	pub fn eval(&self, point: &[F]) -> F {
		ring_switch::eval_rs_eq(&self.eval_point_high, point, &self.eq_r_double_prime)
	}
}

/// Typed PCS-opening output shared by native and replay verification paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcsOpeningOutput<F, Relation> {
	pub relation: Relation,
	pub sumcheck_claim: F,
	pub opened: basefold::OpenedLinearRelation<F>,
	pub sampling: basefold::SamplingTrace<F>,
	pub transparent_eval: F,
}

impl<F, Relation> PcsOpeningOutput<F, Relation>
where
	F: Field + core::ops::Mul<Output = F> + core::ops::Sub<Output = F>,
{
	/// Return the final consistency residual for this opened PCS relation.
	pub fn consistency_error(&self) -> F {
		self.opened.consistency_error(self.transparent_eval)
	}

	/// Replace the relation payload while preserving the opened PCS state.
	pub fn map_relation<Relation2>(
		self,
		f: impl FnOnce(Relation) -> Relation2,
	) -> PcsOpeningOutput<F, Relation2> {
		PcsOpeningOutput {
			relation: f(self.relation),
			sumcheck_claim: self.sumcheck_claim,
			opened: self.opened,
			sampling: self.sampling,
			transparent_eval: self.transparent_eval,
		}
	}
}

/// Authenticated PCS opening before the final pure IOP semantic finalization step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPcsOpening<F, Relation, Opening> {
	pub relation: Relation,
	pub sumcheck_claim: F,
	pub opening: Opening,
}

/// IOP-level semantic PCS-opening output with the vendor-normalized ring-switch relation.
pub type IopPcsOpeningOutput<F> = PcsOpeningOutput<F, RingSwitchEqRelation<F>>;

/// Authenticated IOP-level PCS opening with the vendor-normalized ring-switch relation.
pub type AuthenticatedIopPcsOpening<F, D> = AuthenticatedPcsOpening<
	F,
	RingSwitchEqRelation<F>,
	basefold::AuthenticatedLinearRelationOpening<F, D>,
>;
