// Copyright 2026 The Binius Developers

//! Extraction-oriented scripted RingSwitch verifier.
//!
//! This module provides a monomorphic, plain-data replay of the RingSwitch verifier slice. It is
//! intended for extraction experiments where the generic `IPVerifierChannel` boundary is already
//! semantically right but a plain-data interpreter is more reliable for current extraction tools.

use binius_iop::basefold_extract::F;
use binius_iop::protocol_boundary::StatementTranscriptProtocol;

use crate::pcs::RingSwitchEqRelation as NormalizedRingSwitchEqRelation;
use crate::ring_switch;

pub(crate) const LOG_PACKING: usize = 7;
pub(crate) const PACKING_DEGREE: usize = 1 << LOG_PACKING;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractError {
	MissingObject,
	InvalidAssert,
	UnconsumedTranscript,
}

/// Monomorphic RingSwitch statement exported to Hax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractRingSwitchStatement<F: ExtractField> {
	pub witness_eval: F,
	pub eval_point: Vec<ExtractField>,
}

/// Monomorphic prover-message view for RingSwitch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractRingSwitchProofView<F: ExtractField> {
	pub messages: Vec<ExtractField>,
}

/// Monomorphic verifier-randomness view for RingSwitch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractRingSwitchSamplingView<F: ExtractField> {
	pub challenges: Vec<ExtractField>,
}

/// Monomorphic public-coin interaction view for RingSwitch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractRingSwitchTranscriptView<F: ExtractField> {
	pub proof: ExtractRingSwitchProofView<F>,
	pub sampling: ExtractRingSwitchSamplingView<F>,
}

/// Thin protocol-boundary marker for the extraction-oriented RingSwitch verifier.
pub struct ExtractRingSwitchProtocol<F: ExtractField>;

#[derive(Debug, Clone, Default)]
pub struct ExtractRingSwitchChannel<F: ExtractField> {
	pub messages: Vec<ExtractField>,
	pub challenges: Vec<ExtractField>,

	message_pos: usize,
	challenge_pos: usize,
}

impl<F: ExtractField> ExtractRingSwitchChannel<F> {
	pub fn new(messages: Vec<ExtractField>, challenges: Vec<ExtractField>) -> Self {
		Self {
			messages,
			challenges,
			message_pos: 0,
			challenge_pos: 0,
		}
	}

	pub fn recv_many(&mut self, n: usize) -> Result<Vec<ExtractField>, ExtractError> {
		let end = self.message_pos + n;
		if let Some(values) = self.messages.get(self.message_pos..end) {
			self.message_pos = end;
			Ok(values.to_vec())
		} else {
			Err(ExtractError::MissingObject)
		}
	}

	pub fn sample_many(&mut self, n: usize) -> Result<Vec<ExtractField>, ExtractError> {
		let end = self.challenge_pos + n;
		if let Some(values) = self.challenges.get(self.challenge_pos..end) {
			self.challenge_pos = end;
			Ok(values.to_vec())
		} else {
			Err(ExtractError::MissingObject)
		}
	}

	pub fn assert_zero(&mut self, value: F) -> Result<(), ExtractError> {
		if value == F::ZERO {
			Ok(())
		} else {
			Err(ExtractError::InvalidAssert)
		}
	}

	pub fn is_consumed(&self) -> bool {
		self.message_pos == self.messages.len() && self.challenge_pos == self.challenges.len()
	}
}

impl From<&ExtractRingSwitchTranscriptView<F>> for ExtractRingSwitchChannel<F> {
	fn from(value: &ExtractRingSwitchTranscriptView<F>) -> Self {
		Self::new(
			value.proof.messages.clone(),
			value.sampling.challenges.clone(),
		)
	}
}

/// Monomorphic RingSwitch relation exported to Hax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractRingSwitchEqRelation<F: ExtractField> {
	pub eval_point_high: Vec<ExtractField>,
	pub eq_r_double_prime: Vec<ExtractField>,
}

impl From<NormalizedRingSwitchEqRelation<ExtractField>> for ExtractRingSwitchEqRelation<F> {
	fn from(value: NormalizedRingSwitchEqRelation<ExtractField>) -> Self {
		Self {
			eval_point_high: value.eval_point_high,
			eq_r_double_prime: value.eq_r_double_prime,
		}
	}
}

impl From<ring_switch::RingSwitchEqRelation<ExtractField>> for ExtractRingSwitchEqRelation<F> {
	fn from(value: ring_switch::RingSwitchEqRelation<ExtractField>) -> Self {
		NormalizedRingSwitchEqRelation::from(value).into()
	}
}

impl From<ExtractRingSwitchEqRelation<F>> for NormalizedRingSwitchEqRelation<ExtractField> {
	fn from(value: ExtractRingSwitchEqRelation<F>) -> Self {
		Self {
			eval_point_high: value.eval_point_high,
			eq_r_double_prime: value.eq_r_double_prime,
		}
	}
}

pub fn eval_relation_extract(
	relation: &ExtractRingSwitchEqRelation<F>,
	query: &[F],
) -> F {
	eval_rs_eq_extract(&relation.eval_point_high, query, &relation.eq_r_double_prime)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractRingSwitchOutput<F: ExtractField> {
	pub relation: ExtractRingSwitchEqRelation<F>,
	pub sumcheck_claim: F,
}

impl<F: ExtractField> ExtractRingSwitchStatement<F> {
	pub fn verify_transcript(
		&self,
		transcript: &ExtractRingSwitchTranscriptView<F>,
	) -> Result<ExtractRingSwitchOutput<F>, ExtractError> {
		ExtractRingSwitchProtocol<F>::verify_statement_transcript(self, transcript)
	}
}

impl StatementTranscriptProtocol for ExtractRingSwitchProtocol<F> {
	type Statement = ExtractRingSwitchStatement<F>;
	type TranscriptView = ExtractRingSwitchTranscriptView<F>;
	type Output = ExtractRingSwitchOutput<F>;
	type Error = ExtractError;

	fn verify_statement_transcript(
		statement: &Self::Statement,
		transcript: &Self::TranscriptView,
	) -> Result<Self::Output, Self::Error> {
		verify_statement_transcript_extract(statement, transcript)
	}
}

pub fn verify_statement_transcript_extract(
	statement: &ExtractRingSwitchStatement<F>,
	transcript: &ExtractRingSwitchTranscriptView<F>,
) -> Result<ExtractRingSwitchOutput<F>, ExtractError> {
	let mut channel = ExtractRingSwitchChannel<F>::from(transcript);
	let output = verify_scripted_extract(
		statement.witness_eval,
		&statement.eval_point,
		&mut channel,
	)?;
	if channel.is_consumed() {
		Ok(output)
	} else {
		Err(ExtractError::UnconsumedTranscript)
	}
}

pub(crate) fn evaluate_multilinear_scalars(
	mut evals: Vec<ExtractField>,
	point: &[F],
) -> F {
	assert_eq!(evals.len(), 1 << point.len(), "precondition: evals length must be 2^point.len()");

	let mut log_half_len = point.len();
	while log_half_len > 0 {
		log_half_len -= 1;
		let half_len = 1 << log_half_len;
		let point_i = point[log_half_len];
		let mut next = Vec::with_capacity(half_len);
		let mut j = 0;
		while j < half_len {
			let delta = evals[j + half_len] - evals[j];
			next.push(evals[j] + point_i * delta);
			j += 1;
		}
		evals = next;
	}

	evals[0]
}

pub(crate) fn eq_ind_partial_eval_scalars(point: &[F]) -> Vec<ExtractField> {
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

pub(crate) fn transpose_basis_rows(values: &[F]) -> Vec<ExtractField> {
	assert_eq!(
		values.len(),
		PACKING_DEGREE,
		"precondition: values length must equal the extension degree"
	);

	let mut basis_rows = Vec::with_capacity(PACKING_DEGREE);
	let mut basis_i = 0;
	while basis_i < PACKING_DEGREE {
		basis_rows.push(ExtractField::new(1u128 << basis_i));
		basis_i += 1;
	}
	let mut transposed = Vec::with_capacity(PACKING_DEGREE);
	let mut init = 0;
	while init < PACKING_DEGREE {
		transposed.push(F::ZERO);
		init += 1;
	}

	let mut row = 0;
	while row < PACKING_DEGREE {
		let value = values[row];
		let row_basis = basis_rows[row];
		let value_bits = value.val();

		let mut col = 0;
		while col < PACKING_DEGREE {
			if ((value_bits >> col) & 1) == 1 {
				let mut next = Vec::with_capacity(PACKING_DEGREE);
				let mut i = 0;
				while i < PACKING_DEGREE {
					let entry = if i == col {
						transposed[i] + row_basis
					} else {
						transposed[i]
					};
					next.push(entry);
					i += 1;
				}
				transposed = next;
			}
			col += 1;
		}

		row += 1;
	}

	transposed
}

pub(crate) fn eval_rs_eq_extract(
	z_vals: &[F],
	query: &[F],
	expanded_row_batch_query: &[F],
) -> F {
	assert_eq!(z_vals.len(), query.len(), "precondition: z_vals and query must be the same length");
	assert_eq!(
		expanded_row_batch_query.len(),
		PACKING_DEGREE,
		"precondition: expanded_row_batch_query length must equal the extension degree"
	);

	let mut tensor_eval = Vec::with_capacity(PACKING_DEGREE);
	let mut init = 0;
	while init < PACKING_DEGREE {
		if init == 0 {
			tensor_eval.push(F::ONE);
		} else {
			tensor_eval.push(F::ZERO);
		}
		init += 1;
	}

	let mut i = 0;
	while i < z_vals.len() {
		let vert_i = z_vals[i];
		let hztl_i = query[i];

		let mut vert_scaled = Vec::with_capacity(PACKING_DEGREE);
		let mut j = 0;
		while j < PACKING_DEGREE {
			vert_scaled.push(tensor_eval[j] * vert_i);
			j += 1;
		}

		let mut hztl_scaled = transpose_basis_rows(&tensor_eval);
		let mut j = 0;
		let mut hztl_scaled_next = Vec::with_capacity(PACKING_DEGREE);
		while j < PACKING_DEGREE {
			hztl_scaled_next.push(hztl_scaled[j] * hztl_i);
			j += 1;
		}
		hztl_scaled = hztl_scaled_next;
		hztl_scaled = transpose_basis_rows(&hztl_scaled);

		let mut next_tensor_eval = Vec::with_capacity(PACKING_DEGREE);
		let mut j = 0;
		while j < PACKING_DEGREE {
			next_tensor_eval.push(tensor_eval[j] + vert_scaled[j] + hztl_scaled[j]);
			j += 1;
		}
		tensor_eval = next_tensor_eval;

		i += 1;
	}

	let folded = transpose_basis_rows(&tensor_eval);
	let mut acc = F::ZERO;
	let mut i = 0;
	while i < PACKING_DEGREE {
		acc = acc + folded[i] * expanded_row_batch_query[i];
		i += 1;
	}
	acc
}

pub fn verify_scripted_extract(
	evaluation_claim: F,
	eval_point: &[F],
	channel: &mut ExtractRingSwitchChannel<F>,
) -> Result<ExtractRingSwitchOutput<F>, ExtractError> {
	let (eval_point_low, eval_point_high) = eval_point.split_at(LOG_PACKING);

	let s_hat_v = channel.recv_many(PACKING_DEGREE)?;

	let computed_claim = evaluate_multilinear_scalars(s_hat_v.clone(), eval_point_low);
	channel.assert_zero(evaluation_claim - computed_claim)?;

	let s_hat_u = transpose_basis_rows(&s_hat_v);

	let r_double_prime = channel.sample_many(LOG_PACKING)?;
	let eq_r_double_prime = eq_ind_partial_eval_scalars(&r_double_prime);
	let sumcheck_claim = evaluate_multilinear_scalars(s_hat_u, &r_double_prime);

	Ok(ExtractRingSwitchOutput<F> {
		relation: ExtractRingSwitchEqRelation<F> {
			eval_point_high: eval_point_high.to_vec(),
			eq_r_double_prime,
		},
		sumcheck_claim,
	})
}

#[cfg(test)]
mod tests {
	use binius_ip::channel::IPVerifierChannel;
	use binius_math::test_utils::random_scalars;
	use rand::{SeedableRng, rngs::StdRng};

	use super::{
		F, ExtractRingSwitchChannel<F>, LOG_PACKING, PACKING_DEGREE,
		eval_rs_eq_extract, evaluate_multilinear_scalars,
		verify_scripted_extract,
	};
	use crate::ring_switch;

	#[derive(Debug, Clone)]
	struct GenericScriptedChannel {
		messages: Vec<ExtractField>,
		challenges: Vec<ExtractField>,
		message_pos: usize,
		challenge_pos: usize,
	}

	impl GenericScriptedChannel {
		fn new(messages: Vec<ExtractField>, challenges: Vec<ExtractField>) -> Self {
			Self {
				messages,
				challenges,
				message_pos: 0,
				challenge_pos: 0,
			}
		}
	}

	impl IPVerifierChannel<ExtractField> for GenericScriptedChannel {
		type Elem = F;

		fn recv_one(&mut self) -> Result<Self::Elem, binius_ip::channel::Error> {
			if let Some(value) = self.messages.get(self.message_pos) {
				self.message_pos += 1;
				Ok(*value)
			} else {
				Err(binius_ip::channel::Error::ProofEmpty)
			}
		}

		fn recv_array<const N: usize>(
			&mut self,
		) -> Result<[Self::Elem; N], binius_ip::channel::Error> {
			let end = self.message_pos + N;
			if let Some(values) = self.messages.get(self.message_pos..end) {
				self.message_pos = end;
				Ok(std::array::from_fn(|i| values[i]))
			} else {
				Err(binius_ip::channel::Error::ProofEmpty)
			}
		}

		fn sample(&mut self) -> Self::Elem {
			let value = self.challenges[self.challenge_pos];
			self.challenge_pos += 1;
			value
		}

		fn observe_one(&mut self, val: F) -> Self::Elem {
			val
		}

		fn observe_many(&mut self, vals: &[F]) -> Vec<Self::Elem> {
			vals.to_vec()
		}

		fn assert_zero(&mut self, val: Self::Elem) -> Result<(), binius_ip::channel::Error> {
			if val == F::ZERO {
				Ok(())
			} else {
				Err(binius_ip::channel::Error::InvalidAssert)
			}
		}
	}

	#[test]
	fn extract_matches_generic_ring_switch_verifier() {
		let mut rng = StdRng::seed_from_u64(0);

		let s_hat_v = random_scalars::<ExtractField>(&mut rng, PACKING_DEGREE);
		let eval_point = random_scalars::<ExtractField>(&mut rng, LOG_PACKING + 4);
		let evaluation_claim =
			evaluate_multilinear_scalars(s_hat_v.clone(), &eval_point[..LOG_PACKING]);
		let r_double_prime = random_scalars::<ExtractField>(&mut rng, LOG_PACKING);

		let generic_output = {
			let mut channel = GenericScriptedChannel::new(s_hat_v.clone(), r_double_prime.clone());
			ring_switch::verify(evaluation_claim, &eval_point, &mut channel).unwrap()
		};

		let mut extract_channel = ExtractRingSwitchChannel<F> {
			messages: s_hat_v,
			challenges: r_double_prime,
			..Default::default()
		};
		let extract_output =
			verify_scripted_extract(evaluation_claim, &eval_point, &mut extract_channel)
				.unwrap();

		assert_eq!(
			generic_output.relation.eq_r_double_prime,
			extract_output.relation.eq_r_double_prime
		);
		assert_eq!(generic_output.sumcheck_claim, extract_output.sumcheck_claim);
		assert!(extract_channel.is_consumed());
	}

	#[test]
	fn extract_eval_rs_eq_matches_generic_version() {
		let mut rng = StdRng::seed_from_u64(1);

		let z_vals = random_scalars::<ExtractField>(&mut rng, 6);
		let query = random_scalars::<ExtractField>(&mut rng, 6);
		let expanded_row_batch_query = random_scalars::<ExtractField>(&mut rng, PACKING_DEGREE);

		let generic = ring_switch::eval_rs_eq(&z_vals, &query, &expanded_row_batch_query);
		let extracted = eval_rs_eq_extract(&z_vals, &query, &expanded_row_batch_query);

		assert_eq!(generic, extracted);
	}
}
