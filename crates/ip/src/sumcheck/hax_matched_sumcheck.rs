// Copyright 2026 The Binius Developers
//
//! Minimal **matched** single-round sumcheck over domain `{0, 1}` in `ZMod 17`,
//! kept free of `binius_field::Field` so it is easy to extract with Hax and to
//! align with ArkLib `Sumcheck.roundCheck` / `advance` on `ZMod 17`.
//
//! Mirror module (for extraction): `binius_iop::sumcheck_matched_extract` (same
//! implementation via `#[path]` from `binius-iop`).

/// Prime modulus; matches FRIBinius bridge `HaxMatchedSumcheckDemo.MATCHED_SUMCHECK_PRIME`
/// (`bridge/FRIBiniusBridge/HaxMatchedSumcheck.lean`).
pub const MATCHED_SUMCHECK_PRIME: u64 = 17;

#[inline]
pub fn matched_mod_reduce(x: u64) -> u64 {
	x % MATCHED_SUMCHECK_PRIME
}

#[inline]
pub fn matched_add(a: u64, b: u64) -> u64 {
	matched_mod_reduce(a + b)
}

#[inline]
pub fn matched_mul(a: u64, b: u64) -> u64 {
	matched_mod_reduce(a * b)
}

/// Univariate `c0 + c1 * X` evaluated at `x` in `ZMod MATCHED_SUMCHECK_PRIME` (inputs reduced mod p).
#[inline]
pub fn matched_univariate_eval(c0: u64, c1: u64, x: u64) -> u64 {
	matched_add(c0, matched_mul(c1, matched_mod_reduce(x)))
}

/// Sumcheck **round check**: `P(0) + P(1) == target` (mod p).
/// Matches `Sumcheck.roundCheck` on domain `![0, 1] : Fin 2 → ZMod p`.
pub fn matched_sumcheck_round_check(target: u64, c0: u64, c1: u64) -> bool {
	let s0 = matched_univariate_eval(c0, c1, 0);
	let s1 = matched_univariate_eval(c0, c1, 1);
	matched_add(s0, s1) == matched_mod_reduce(target)
}

/// **Advance** to the next subclaim: `target' := P(r)`.
/// Matches `Sumcheck.advance` for one round (`CPolynomial.eval r roundPoly`).
#[inline]
pub fn matched_sumcheck_advance(c0: u64, c1: u64, challenge: u64) -> u64 {
	matched_univariate_eval(c0, c1, challenge)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn round_check_linear_example() {
		// P(X) = 3 + 5X: P(0)+P(1) = 3 + 8 = 11
		assert!(matched_sumcheck_round_check(11, 3, 5));
		assert!(!matched_sumcheck_round_check(10, 3, 5));
	}

	#[test]
	fn advance_matches_eval() {
		assert_eq!(matched_sumcheck_advance(3, 5, 4), matched_univariate_eval(3, 5, 4));
	}
}
