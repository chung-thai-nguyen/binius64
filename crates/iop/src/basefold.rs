// Copyright 2025 Irreducible Inc.
// Copyright 2026 The Binius Developers

//! Verifier for the BaseFold sumcheck-PIOP to IP compiler.
//!
//! [BaseFold] is a generalized polynomial commitment scheme that allows compilation of
//! sumcheck-PIOP protocols to IOPs. The protocol is an interactive argument for sumcheck claims
//! of multivariate polynomials defined as the product of a committed multilinear polynomial and a
//! transparent multilinear polynomial. When the transparent polynomial is a multilinear equality
//! indicator, this BaseFold instance becomes a multilinear polynomial commitment scheme. The core
//! idea is to commit the multilinear polynomial using FRI and open the sumcheck claim using an
//! interleaved instance of sumcheck on the composite polynomial and FRI on the committed codeword,
//! sharing folding challenges.
//!
//! This module implements the version specialized for binary field FRI described in [DP24],
//! Section 4. Moreover, this module includes the classic [BCS16] compiler for IOPs to IPs that
//! commits and opens oracle messages using Merkle trees.
//!
//! [BaseFold]: <https://link.springer.com/chapter/10.1007/978-3-031-68403-6_5>
//! [DP24]: <https://eprint.iacr.org/2024/504>
//! [BCS16]: <https://eprint.iacr.org/2016/116>

use binius_field::{BinaryField, Field};
use binius_ip::sumcheck::{RoundCoeffs, RoundProof};
use binius_math::{
	line::extrapolate_line_packed,
	multilinear::eq::eq_ind,
	ntt::{NeighborsLastSingleThread, domain_context::GenericOnTheFly},
};
use binius_transcript::{
	self as transcript, VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::DeserializeBytes;

use crate::{
	fri::{
		self, FRIFoldVerifier, FRIParams,
		verify::{AuthenticatedFRIQueryPhase, FRIQueryVerifier, FRISemanticVerifier},
	},
	merkle_tree::MerkleTreeScheme,
};

/// Verifies a BaseFold protocol interaction.
///
/// See module documentation for protocol description.
///
/// ## Arguments
///
/// * `fri_params` - The FRI parameters
/// * `merkle_scheme` - The Merkle tree scheme
/// * `codeword_commitment` - The commitment to the codeword
/// * `transcript` - The transcript containing the prover's messages and randomness for challenges
/// * `evaluation_claim` - The claimed evaluation of the multilinear polynomial at the evaluation
///   point
///
/// ## Returns
///
/// The [`ReducedOutput`] holding the final FRI value, the final sumcheck value, the verifier's
/// sampled fold challenges, and the sampled FRI query indices.
pub fn verify<F, MTScheme, Challenger_>(
	fri_params: &FRIParams<F>,
	merkle_scheme: &MTScheme,
	codeword_commitment: MTScheme::Digest,
	evaluation_claim: F,
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<ReducedOutput<F>, Error>
where
	F: BinaryField,
	Challenger_: Challenger,
	MTScheme: MerkleTreeScheme<F, Digest: DeserializeBytes>,
{
	let authenticated = open_authenticated(
		fri_params,
		merkle_scheme,
		codeword_commitment,
		evaluation_claim,
		transcript,
	)?;
	verify_authenticated(fri_params, authenticated)
}

pub fn verify_zk<F, MTScheme, Challenger_>(
	fri_params: &FRIParams<F>,
	merkle_scheme: &MTScheme,
	codeword_commitment: MTScheme::Digest,
	sum_claim: F,
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<ReducedOutput<F>, Error>
where
	F: BinaryField,
	Challenger_: Challenger,
	MTScheme: MerkleTreeScheme<F, Digest: DeserializeBytes>,
{
	let authenticated = open_authenticated_zk(
		fri_params,
		merkle_scheme,
		codeword_commitment,
		sum_claim,
		transcript,
	)?;
	verify_authenticated(fri_params, authenticated)
}

/// Authenticated BaseFold / FRI opening after transcript/Merkle checks but before the pure IOP
/// semantic finalization step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedLinearRelationOpening<F, D> {
	pub final_sumcheck_value: F,
	pub sampling: SamplingTrace<F>,
	pub query_phase: AuthenticatedFRIQueryPhase<F, D>,
	pub query_challenge_offset: usize,
}

/// Read the transcript-backed BaseFold opening and authenticate all commitment/opening material,
/// but do not yet run the pure FRI semantic checks.
pub fn open_authenticated<F, MTScheme, Challenger_>(
	fri_params: &FRIParams<F>,
	merkle_scheme: &MTScheme,
	codeword_commitment: MTScheme::Digest,
	evaluation_claim: F,
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<AuthenticatedLinearRelationOpening<F, MTScheme::Digest>, Error>
where
	F: BinaryField,
	Challenger_: Challenger,
	MTScheme: MerkleTreeScheme<F, Digest: DeserializeBytes>,
{
	// The multivariate polynomial evaluated is a degree-2 multilinear composite.
	const DEGREE: usize = 2;
	let n_vars = fri_params.log_msg_len();
	let mut challenges = Vec::with_capacity(n_vars);

	let mut fri_fold_verifier = FRIFoldVerifier::new(fri_params);
	let mut sum = evaluation_claim;

	for _ in 0..n_vars {
		let round_proof = RoundProof(RoundCoeffs(transcript.message().read_vec(DEGREE)?));
		fri_fold_verifier.process_round(&mut transcript.message())?;

		let round_coeffs = round_proof.recover(sum);
		let challenge = transcript.sample();
		sum = round_coeffs.evaluate(challenge);
		challenges.push(challenge);
	}

	// Finalize and get commitments
	fri_fold_verifier.process_round(&mut transcript.message())?;
	let round_commitments = fri_fold_verifier.finalize()?;

	// TODO: Make all commitments after the first non-hiding
	let fri_verifier = FRIQueryVerifier::new(
		fri_params,
		merkle_scheme,
		&codeword_commitment,
		&round_commitments,
		&challenges,
	)?;

	let query_phase = fri_verifier.open_phase(transcript)?;

	Ok(AuthenticatedLinearRelationOpening {
		final_sumcheck_value: sum,
		sampling: SamplingTrace {
			challenges,
			query_indices: query_phase.query_indices.clone(),
		},
		query_phase,
		query_challenge_offset: 0,
	})
}

/// ZK variant of [`open_authenticated`]. The returned sampling trace retains the full verifier
/// randomness, including the leading batch challenge, while `query_challenge_offset = 1` records
/// that transparent-query reconstruction skips that first challenge.
pub fn open_authenticated_zk<F, MTScheme, Challenger_>(
	fri_params: &FRIParams<F>,
	merkle_scheme: &MTScheme,
	codeword_commitment: MTScheme::Digest,
	sum_claim: F,
	transcript: &mut VerifierTranscript<Challenger_>,
) -> Result<AuthenticatedLinearRelationOpening<F, MTScheme::Digest>, Error>
where
	F: BinaryField,
	Challenger_: Challenger,
	MTScheme: MerkleTreeScheme<F, Digest: DeserializeBytes>,
{
	const DEGREE: usize = 2;

	assert_eq!(fri_params.log_batch_size(), 1); // precondition

	let mask_claim = transcript.message().read::<F>()?;
	let n_vars = fri_params.rs_code().log_dim();
	let mut challenges = Vec::with_capacity(n_vars + 1);

	let mut fri_fold_verifier = FRIFoldVerifier::new(fri_params);
	let batch_challenge = transcript.sample();
	let mut sum = extrapolate_line_packed(sum_claim, mask_claim, batch_challenge);

	fri_fold_verifier.process_round(&mut transcript.message())?;
	challenges.push(batch_challenge);

	for _ in 0..n_vars {
		let round_proof = RoundProof(RoundCoeffs(transcript.message().read_vec(DEGREE)?));
		fri_fold_verifier.process_round(&mut transcript.message())?;

		let round_coeffs = round_proof.recover(sum);
		let challenge = transcript.sample();
		sum = round_coeffs.evaluate(challenge);
		challenges.push(challenge);
	}

	fri_fold_verifier.process_round(&mut transcript.message())?;
	let round_commitments = fri_fold_verifier.finalize()?;

	let fri_verifier = FRIQueryVerifier::new(
		fri_params,
		merkle_scheme,
		&codeword_commitment,
		&round_commitments,
		&challenges,
	)?;

	let query_phase = fri_verifier.open_phase(transcript)?;

	Ok(AuthenticatedLinearRelationOpening {
		final_sumcheck_value: sum,
		sampling: SamplingTrace {
			challenges,
			query_indices: query_phase.query_indices.clone(),
		},
		query_phase,
		query_challenge_offset: 1,
	})
}

/// Complete the pure IOP semantic verification of an authenticated BaseFold / FRI opening.
pub fn verify_authenticated<F, D>(
	fri_params: &FRIParams<F>,
	authenticated: AuthenticatedLinearRelationOpening<F, D>,
) -> Result<ReducedOutput<F>, Error>
where
	F: BinaryField,
	D: Clone,
{
	let subspace = fri_params.rs_code().subspace();
	let domain_context = GenericOnTheFly::generate_from_subspace(subspace);
	let ntt = NeighborsLastSingleThread::new(domain_context);
	let semantic_verifier = FRISemanticVerifier::new(fri_params, &authenticated.sampling.challenges)?;
	let opened_fri = semantic_verifier.verify_authenticated_phase(&ntt, authenticated.query_phase)?;

	Ok(ReducedOutput {
		final_fri_value: opened_fri.final_value,
		final_sumcheck_value: authenticated.final_sumcheck_value,
		challenges: authenticated.sampling.challenges,
		query_indices: authenticated.sampling.query_indices,
	})
}

/// Complete an authenticated BaseFold / FRI opening all the way to the typed linear-relation
/// opening object consumed by the final transparent-polynomial check.
pub fn finalize_authenticated_opening<F, D>(
	fri_params: &FRIParams<F>,
	authenticated: AuthenticatedLinearRelationOpening<F, D>,
) -> Result<OpenedLinearRelationWithSampling<F>, Error>
where
	F: BinaryField + Clone,
	D: Clone,
{
	let final_output = verify_authenticated(fri_params, authenticated.clone())?;
	let query_point =
		query_point_from_challenges(&authenticated.sampling.challenges[authenticated.query_challenge_offset..]);
	Ok(OpenedLinearRelationWithSampling {
		opened: OpenedLinearRelation {
			final_fri_value: final_output.final_fri_value,
			final_sumcheck_value: authenticated.final_sumcheck_value,
			query_point,
		},
		sampling: authenticated.sampling,
	})
}

/// Output type of the [`verify`] function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReducedOutput<F> {
	pub final_fri_value: F,
	pub final_sumcheck_value: F,
	pub challenges: Vec<F>,
	pub query_indices: Vec<usize>,
}

/// Explicit verifier randomness used while opening a committed linear relation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamplingTrace<F> {
	pub challenges: Vec<F>,
	pub query_indices: Vec<usize>,
}

/// Semantic opening output used by the final transparent-polynomial consistency check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedLinearRelation<F> {
	pub final_fri_value: F,
	pub final_sumcheck_value: F,
	pub query_point: Vec<F>,
}

/// Fully reified opened linear relation together with the verifier randomness used to obtain it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedLinearRelationWithSampling<F> {
	pub opened: OpenedLinearRelation<F>,
	pub sampling: SamplingTrace<F>,
}

/// Convert folding challenges into the low-to-high query-point order expected by transparent
/// multilinear evaluations.
pub fn query_point_from_challenges<F: Clone>(challenges: &[F]) -> Vec<F> {
	let mut query_point = Vec::with_capacity(challenges.len());
	let mut i = challenges.len();
	while i > 0 {
		i -= 1;
		query_point.push(challenges[i].clone());
	}
	query_point
}

/// Build the semantic opening output from the final BaseFold / FRI values and the relevant fold
/// challenges.
pub fn opened_linear_relation_from_challenges<F: Clone>(
	final_fri_value: F,
	final_sumcheck_value: F,
	challenges: &[F],
) -> OpenedLinearRelation<F> {
	OpenedLinearRelation {
		final_fri_value,
		final_sumcheck_value,
		query_point: query_point_from_challenges(challenges),
	}
}

impl<F> ReducedOutput<F>
where
	F: Clone,
{
	/// Reify the verifier randomness used by BaseFold / FRI while opening the linear relation.
	pub fn sampling_trace(&self) -> SamplingTrace<F> {
		SamplingTrace {
			challenges: self.challenges.clone(),
			query_indices: self.query_indices.clone(),
		}
	}

	/// Reify the semantic opening object consumed by the final transparent-polynomial check.
	pub fn opened_linear_relation(&self) -> OpenedLinearRelation<F> {
		opened_linear_relation_from_challenges(
			self.final_fri_value.clone(),
			self.final_sumcheck_value.clone(),
			&self.challenges,
		)
	}

	/// Reify both the semantic opening object and the verifier randomness used to obtain it.
	pub fn opened_linear_relation_with_sampling(&self) -> OpenedLinearRelationWithSampling<F> {
		OpenedLinearRelationWithSampling {
			opened: self.opened_linear_relation(),
			sampling: self.sampling_trace(),
		}
	}

	/// Move out the verifier randomness used by BaseFold / FRI while opening the linear relation.
	pub fn into_sampling_trace(self) -> SamplingTrace<F> {
		SamplingTrace {
			challenges: self.challenges,
			query_indices: self.query_indices,
		}
	}

	/// Move out the semantic opening object consumed by the final transparent-polynomial check.
	pub fn into_opened_linear_relation(self) -> OpenedLinearRelation<F> {
		OpenedLinearRelation {
			final_fri_value: self.final_fri_value,
			final_sumcheck_value: self.final_sumcheck_value,
			query_point: query_point_from_challenges(&self.challenges),
		}
	}

	/// Move out both the semantic opening object and the verifier randomness used to obtain it.
	pub fn into_opened_linear_relation_with_sampling(self) -> OpenedLinearRelationWithSampling<F> {
		let query_point = query_point_from_challenges(&self.challenges);
		OpenedLinearRelationWithSampling {
			opened: OpenedLinearRelation {
				final_fri_value: self.final_fri_value,
				final_sumcheck_value: self.final_sumcheck_value,
				query_point,
			},
			sampling: SamplingTrace {
				challenges: self.challenges,
				query_indices: self.query_indices,
			},
		}
	}
}

impl<F> OpenedLinearRelation<F>
where
	F: Field,
{
	/// Return the consistency-check residual
	/// `final_sumcheck_value - final_fri_value * transparent_eval`.
	pub fn consistency_error(&self, transparent_eval: F) -> F {
		self.final_sumcheck_value - self.final_fri_value * transparent_eval
	}
}

/// Verifies that the final FRI oracle is consistent with the sumcheck
///
/// This assertion verifies that the FRI and Sumcheck proof belong to the same
/// commitment. It should be called after the transcript has been verified.
///
/// ## Arguments
///
/// * `fri_final_oracle` - The final FRI oracle
/// * `sumcheck_final_claim` - The final sumcheck claim
/// * `evaluation_point` - The evaluation point
/// * `challenges` - The challenges used in the sumcheck rounds
///
/// # Returns
///
/// A boolean indicating if the final FRI oracle is consistent with the sumcheck claim.
pub fn sumcheck_fri_consistency<F: Field>(
	fri_final_oracle: F,
	sumcheck_final_claim: F,
	evaluation_point: &[F],
	challenges: Vec<F>,
) -> bool {
	let opened =
		opened_linear_relation_from_challenges(fri_final_oracle, sumcheck_final_claim, &challenges);
	opened.final_fri_value * eq_ind(evaluation_point, &opened.query_point) == opened.final_sumcheck_value
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("FRI: {0}")]
	FRI(#[source] fri::Error),
	#[error("transcript: {0}")]
	Transcript(#[from] transcript::Error),
	#[error("verification error: {0}")]
	Verification(#[from] VerificationError),
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
	#[error("FRI: {0}")]
	FRI(#[from] fri::VerificationError),
}

impl From<fri::Error> for Error {
	fn from(err: fri::Error) -> Self {
		match err {
			fri::Error::Verification(err) => Error::Verification(err.into()),
			_ => Error::FRI(err),
		}
	}
}
