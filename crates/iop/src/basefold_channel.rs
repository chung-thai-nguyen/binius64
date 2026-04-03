// Copyright 2026 The Binius Developers

//! BaseFold-based implementation of the IOP verifier channel.
//!
//! This module provides [`BaseFoldVerifierChannel`], which implements [`IOPVerifierChannel`] using
//! FRI commitment and BaseFold opening protocols.

use binius_field::BinaryField;
use binius_ip::channel::IPVerifierChannel;
use binius_transcript::{
	VerifierTranscript,
	fiat_shamir::{CanSample, Challenger},
};
use binius_utils::DeserializeBytes;

use crate::{
	basefold,
	channel::{
		AuthenticatedOpeningVerifierChannel, Error, IOPVerifierChannel,
		OracleCommitmentVerifierChannel, OracleLinearRelation, OracleSpec,
	},
	fri::FRIParams,
	merkle_tree::MerkleTreeScheme,
};

/// Oracle handle returned by [`BaseFoldVerifierChannel::recv_oracle`].
#[derive(Debug, Clone, Copy)]
pub struct BaseFoldOracle {
	index: usize,
}

/// A verifier channel that uses BaseFold for oracle commitment and opening.
///
/// This channel wraps a [`VerifierTranscript`] and provides oracle operations using
/// FRI commitment (Reed-Solomon encoding + Merkle tree) and BaseFold opening protocols.
///
/// # Type Parameters
///
/// - `'a`: Lifetime for borrowed references
/// - `F`: The binary field type
/// - `MerkleScheme_`: The Merkle tree scheme for commitments
/// - `Challenger_`: The Fiat-Shamir challenger
pub struct BaseFoldVerifierChannel<'a, F, MerkleScheme_, Challenger_>
where
	F: BinaryField,
	MerkleScheme_: MerkleTreeScheme<F>,
	Challenger_: Challenger,
{
	/// Verifier transcript for Fiat-Shamir (borrowed).
	transcript: &'a mut VerifierTranscript<Challenger_>,
	/// Merkle tree scheme (borrowed).
	merkle_scheme: &'a MerkleScheme_,
	/// Oracle specifications (borrowed).
	oracle_specs: &'a [OracleSpec],
	/// Precomputed FRI params per oracle (borrowed).
	fri_params: &'a [FRIParams<F>],
	/// Received oracle commitments.
	oracle_commitments: Vec<MerkleScheme_::Digest>,
	/// Next oracle index.
	next_oracle_index: usize,
}

impl<'a, F, MerkleScheme_, Challenger_> BaseFoldVerifierChannel<'a, F, MerkleScheme_, Challenger_>
where
	F: BinaryField,
	MerkleScheme_: MerkleTreeScheme<F, Digest: DeserializeBytes>,
	Challenger_: Challenger,
{
	/// Creates a new BaseFold verifier channel from precomputed FRI parameters.
	///
	/// This constructor is useful when FRI parameters have already been computed
	/// (e.g., by a [`crate::basefold_compiler::BaseFoldVerifierCompiler`]).
	///
	/// # Arguments
	///
	/// * `transcript` - The verifier transcript for Fiat-Shamir (borrowed)
	/// * `merkle_scheme` - The Merkle tree scheme (borrowed)
	/// * `oracle_specs` - Specifications for each oracle to be committed (borrowed)
	/// * `fri_params` - Precomputed FRI parameters for each oracle (borrowed)
	pub fn from_precomputed(
		transcript: &'a mut VerifierTranscript<Challenger_>,
		merkle_scheme: &'a MerkleScheme_,
		oracle_specs: &'a [OracleSpec],
		fri_params: &'a [FRIParams<F>],
	) -> Self {
		Self {
			transcript,
			merkle_scheme,
			oracle_specs,
			fri_params,
			oracle_commitments: Vec::new(),
			next_oracle_index: 0,
		}
	}

	/// Returns a reference to the underlying transcript.
	pub fn transcript(&self) -> &VerifierTranscript<Challenger_> {
		self.transcript
	}

	/// Run the BaseFold opening protocol for one committed oracle relation and return the typed
	/// semantic opening object used by the final transparent-polynomial check.
	pub fn open_linear_relation(
		&mut self,
		oracle: BaseFoldOracle,
		claim: F,
	) -> Result<basefold::OpenedLinearRelation<F>, Error> {
		self.open_linear_relation_with_sampling(oracle, claim)
			.map(|opened| opened.opened)
	}

	/// Run the BaseFold opening protocol for one committed oracle relation and return both the
	/// semantic opening object and the verifier randomness used to obtain it.
	pub fn open_linear_relation_with_sampling(
		&mut self,
		oracle: BaseFoldOracle,
		claim: F,
	) -> Result<basefold::OpenedLinearRelationWithSampling<F>, Error> {
		let authenticated = self.open_authenticated_linear_relation(oracle, claim)?;
		Ok(basefold::finalize_authenticated_opening(
			&self.fri_params[oracle.index],
			authenticated,
		)?)
	}

	/// Run the BaseFold opening protocol for one committed oracle relation and return the
	/// authenticated opening object before the pure IOP semantic finalization step.
	pub fn open_authenticated_linear_relation(
		&mut self,
		oracle: BaseFoldOracle,
		claim: F,
	) -> Result<basefold::AuthenticatedLinearRelationOpening<F, MerkleScheme_::Digest>, Error> {
		assert!(
			self.remaining_oracle_specs().is_empty(),
			"open_linear_relation called but {} oracle specs remaining",
			self.remaining_oracle_specs().len()
		);

		let index = oracle.index;
		assert!(
			index < self.oracle_commitments.len(),
			"oracle index {index} out of bounds, expected < {}",
			self.oracle_commitments.len()
		);

		let fri_params = &self.fri_params[index];
		let commitment = self.oracle_commitments[index].clone();
		let basefold_output = basefold::open_authenticated(
			fri_params,
			self.merkle_scheme,
			commitment,
			claim,
			self.transcript,
		)?;

		Ok(basefold_output)
	}

	fn verify_linear_relation(
		&mut self,
		relation: OracleLinearRelation<BaseFoldOracle, F>,
	) -> Result<(), Error> {
		let opened = self.open_linear_relation(relation.oracle, relation.claim)?;
		let transparent_eval = (relation.transparent)(&opened.query_point);
		self.assert_zero(opened.consistency_error(transparent_eval))?;
		Ok(())
	}
}

impl<F, MerkleScheme_, Challenger_> IPVerifierChannel<F>
	for BaseFoldVerifierChannel<'_, F, MerkleScheme_, Challenger_>
where
	F: BinaryField,
	MerkleScheme_: MerkleTreeScheme<F, Digest: DeserializeBytes>,
	Challenger_: Challenger,
{
	type Elem = F;

	fn recv_one(&mut self) -> Result<F, binius_ip::channel::Error> {
		self.transcript
			.message()
			.read_scalar()
			.map_err(|_| binius_ip::channel::Error::ProofEmpty)
	}

	fn recv_many(&mut self, n: usize) -> Result<Vec<F>, binius_ip::channel::Error> {
		self.transcript
			.message()
			.read_scalar_slice(n)
			.map_err(|_| binius_ip::channel::Error::ProofEmpty)
	}

	fn recv_array<const N: usize>(&mut self) -> Result<[F; N], binius_ip::channel::Error> {
		self.transcript
			.message()
			.read()
			.map_err(|_| binius_ip::channel::Error::ProofEmpty)
	}

	fn sample(&mut self) -> F {
		CanSample::sample(&mut self.transcript)
	}

	fn observe_one(&mut self, val: F) -> F {
		self.transcript.observe().write_scalar(val);
		val
	}

	fn observe_many(&mut self, vals: &[F]) -> Vec<F> {
		self.transcript.observe().write_scalar_slice(vals);
		vals.to_vec()
	}

	fn assert_zero(&mut self, val: F) -> Result<(), binius_ip::channel::Error> {
		if val == F::ZERO {
			Ok(())
		} else {
			Err(binius_ip::channel::Error::InvalidAssert)
		}
	}
}

impl<F, MerkleScheme_, Challenger_> OracleCommitmentVerifierChannel<F>
	for BaseFoldVerifierChannel<'_, F, MerkleScheme_, Challenger_>
where
	F: BinaryField,
	MerkleScheme_: MerkleTreeScheme<F, Digest: DeserializeBytes>,
	Challenger_: Challenger,
{
	type Oracle = BaseFoldOracle;

	fn remaining_oracle_specs(&self) -> &[OracleSpec] {
		&self.oracle_specs[self.next_oracle_index..]
	}

	fn recv_oracle(&mut self) -> Result<Self::Oracle, Error> {
		assert!(
			!self.remaining_oracle_specs().is_empty(),
			"recv_oracle called but no remaining oracle specs"
		);

		let index = self.next_oracle_index;

		// Read commitment from transcript
		let commitment = self
			.transcript
			.message()
			.read::<MerkleScheme_::Digest>()
			.map_err(|_| Error::ProofEmpty)?;

		self.oracle_commitments.push(commitment);
		self.next_oracle_index += 1;

		Ok(BaseFoldOracle { index })
	}
}

impl<F, MerkleScheme_, Challenger_> AuthenticatedOpeningVerifierChannel<F>
	for BaseFoldVerifierChannel<'_, F, MerkleScheme_, Challenger_>
where
	F: BinaryField,
	MerkleScheme_: MerkleTreeScheme<F, Digest: DeserializeBytes>,
	Challenger_: Challenger,
{
	type AuthenticatedOpening = basefold::AuthenticatedLinearRelationOpening<F, MerkleScheme_::Digest>;

	fn open_authenticated_linear_relation(
		&mut self,
		oracle: Self::Oracle,
		claim: F,
	) -> Result<Self::AuthenticatedOpening, Error> {
		BaseFoldVerifierChannel::open_authenticated_linear_relation(self, oracle, claim)
	}
}

impl<F, MerkleScheme_, Challenger_> IOPVerifierChannel<F>
	for BaseFoldVerifierChannel<'_, F, MerkleScheme_, Challenger_>
where
	F: BinaryField,
	MerkleScheme_: MerkleTreeScheme<F, Digest: DeserializeBytes>,
	Challenger_: Challenger,
{
	fn verify_oracle_relations(
		&mut self,
		oracle_relations: impl IntoIterator<Item = OracleLinearRelation<Self::Oracle, Self::Elem>>,
	) -> Result<(), Error> {
		for relation in oracle_relations {
			self.verify_linear_relation(relation)?;
		}

		Ok(())
	}
}
