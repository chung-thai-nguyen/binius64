// Copyright 2026 The Binius Developers

//! Thin protocol-boundary traits for extraction-friendly verifier APIs.
//!
//! These traits intentionally abstract only the outer `statement × transcript` verification
//! boundary and the optional authenticated-opening boundary beneath it. They are not meant to
//! encode the full protocol calculus in Rust types.
//!
//! The design goal is:
//! - keep Rust implementation layers explicit and reusable
//! - keep Hax-facing entrypoints concrete and record-oriented
//! - keep the generated Lean surface close to OracleReduction-style statements, transcripts,
//!   authenticated openings, and semantic outputs
//!
//! # Layering: IOP semantic core vs crypto transport (ArkLib bridge)
//!
//! Implementations of [`AuthenticatedStatementTranscriptProtocol`] should treat the two trait
//! methods as a **mandatory split** for formal verification:
//!
//! 1. **`verify_authenticated_statement_transcript`** — **Layer 1 (crypto / commitment
//!    transport).** Consumes `statement × transcript` and returns an *authenticated intermediate*
//!    (Merkle openings, digest-checked data, transcript consumption). This layer is **not** what
//!    ArkLib’s post-commitment `OracleReduction` perfect completeness / RBR-KS theorems state
//!    directly; it is the target of **explicit second lemmas** (commitment scheme, hashing, FS).
//!
//! 2. **`verify_authenticated`** — **Layer 2 (IOP semantic core).** Pure predicate on the
//!    authenticated intermediate (+ statement parameters). This is what should refine to the
//!    paper `OracleReduction` verifier after the transport lemmas connect types and relations.
//!
//! The default [`StatementTranscriptProtocol`] blanket impl composes **Layer 1 then Layer 2** in
//! order. Hax-generated Lean keeps the same `match`-then-continue shape; the handwritten bridge
//! module `FRIBiniusBridge/IOPCoreTransportSplit` names these layers for ArkLib correspondence.

/// Marker for protocols that intentionally separate transport from IOP semantics (documentation + object safety).
pub trait LayeredAuthenticatorVerifier: AuthenticatedStatementTranscriptProtocol {}

/// A protocol whose verifier can be driven directly from a concrete statement and transcript view.
pub trait StatementTranscriptProtocol {
	type Statement;
	type TranscriptView;
	type Output;
	type Error;

	fn verify_statement_transcript(
		statement: &Self::Statement,
		transcript: &Self::TranscriptView,
	) -> Result<Self::Output, Self::Error>;
}

/// A protocol whose verifier exposes an authenticated-opening boundary before the final semantic
/// verification step.
pub trait AuthenticatedStatementTranscriptProtocol {
	type Statement;
	type TranscriptView;
	type Authenticated;
	type Output;
	type Error;

	fn verify_authenticated_statement_transcript(
		statement: &Self::Statement,
		transcript: &Self::TranscriptView,
	) -> Result<Self::Authenticated, Self::Error>;

	fn verify_authenticated(
		statement: &Self::Statement,
		authenticated: Self::Authenticated,
	) -> Result<Self::Output, Self::Error>;
}

impl<T> LayeredAuthenticatorVerifier for T where T: AuthenticatedStatementTranscriptProtocol {}

impl<T> StatementTranscriptProtocol for T
where
	T: AuthenticatedStatementTranscriptProtocol,
{
	type Statement = T::Statement;
	type TranscriptView = T::TranscriptView;
	type Output = T::Output;
	type Error = T::Error;

	fn verify_statement_transcript(
		statement: &Self::Statement,
		transcript: &Self::TranscriptView,
	) -> Result<Self::Output, Self::Error> {
		let authenticated = T::verify_authenticated_statement_transcript(statement, transcript)?;
		T::verify_authenticated(statement, authenticated)
	}
}
