#!/usr/bin/env python3

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


MODULES: dict[str, dict[str, object]] = {
    "crates/verifier/src/ring_switch_extract.rs": {
        "required": [
            "pub struct ExtractRingSwitchStatement",
            "pub struct ExtractRingSwitchTranscriptView",
            "pub struct ExtractRingSwitchProtocol;",
            "impl StatementTranscriptProtocol for ExtractRingSwitchProtocol",
            "pub fn verify_statement_transcript_128b_ghash_extract(",
            "pub fn verify_transcript(",
        ],
    },
    "crates/iop/src/basefold_extract.rs": {
        "required": [
            "pub struct ExtractBasefoldStatement",
            "pub struct ExtractBasefoldTranscriptView",
            "pub struct ExtractAuthenticatedLinearRelationOpening",
            "pub struct ExtractBasefoldProtocol;",
            "impl AuthenticatedStatementTranscriptProtocol for ExtractBasefoldProtocol",
            "pub fn verify_statement_transcript_128b_ghash_extract(",
            "pub fn verify_authenticated_statement_transcript_128b_ghash_extract(",
            "pub fn finalize_authenticated_128b_ghash_extract(",
            "pub fn verify_transcript(",
            "pub fn verify_authenticated_transcript(",
        ],
    },
    "crates/verifier/src/pcs_extract.rs": {
        "required": [
            "pub struct ExtractPcsStatement",
            "pub struct ExtractPcsTranscriptView",
            "pub struct ExtractAuthenticatedPcsOpening",
            "pub struct ExtractPcsProtocol;",
            "impl AuthenticatedStatementTranscriptProtocol for ExtractPcsProtocol",
            "pub fn verify_statement_transcript_128b_ghash_extract(",
            "pub fn verify_authenticated_statement_transcript_128b_ghash_extract(",
            "pub fn finalize_authenticated_128b_ghash_extract(",
            "pub fn verify_transcript(",
            "pub fn verify_authenticated_transcript(",
        ],
    },
}


FORBIDDEN_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"Box\s*<\s*dyn"), "dynamic dispatch / boxed trait objects in extract surface"),
    (re.compile(r"\bdyn\s+[A-Za-z_]"), "trait objects in extract surface"),
    (re.compile(r"\.iter\("), "iterator adapters in extract surface"),
    (re.compile(r"\.iter_mut\("), "iterator adapters in extract surface"),
    (re.compile(r"\.into_iter\("), "iterator adapters in extract surface"),
    (re.compile(r"\.map\("), "functional iterator style in extract surface"),
    (re.compile(r"\.filter\("), "functional iterator style in extract surface"),
    (re.compile(r"\.fold\("), "functional iterator style in extract surface"),
    (re.compile(r"\.zip\("), "iterator zipping in extract surface"),
    (re.compile(r"\.enumerate\("), "iterator enumeration in extract surface"),
    (re.compile(r"\.flat_map\("), "functional iterator style in extract surface"),
    (re.compile(r"\.collect\("), "collection from iterators in extract surface"),
    (re.compile(r"\bIterator::"), "iterator trait helpers in extract surface"),
]


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*", "", text)
    return text


def main() -> int:
    errors: list[str] = []

    for rel_path, cfg in MODULES.items():
        path = ROOT / rel_path
        if not path.exists():
            errors.append(f"missing extract module: {path}")
            continue

        text = path.read_text()
        text_no_comments = strip_comments(text)

        for needle in cfg["required"]:  # type: ignore[index]
            if needle not in text:
                errors.append(f"{path}: missing required authoring-surface item: {needle}")

        for pattern, reason in FORBIDDEN_PATTERNS:
            if pattern.search(text_no_comments):
                errors.append(
                    f"{path}: forbidden pattern `{pattern.pattern}` found "
                    f"({reason})"
                )

    if errors:
        print("extract-surface check failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("extract-surface check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
