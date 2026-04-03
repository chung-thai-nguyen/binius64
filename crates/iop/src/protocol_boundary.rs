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
