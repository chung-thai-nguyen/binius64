# Extraction Reproducibility Guide

This document gives precise, rerunnable steps for extracting the replay-oriented
`RingSwitch + BaseFold / FRI` verifier slice with both `hax` and `aeneas`.

## Quick Start

From the repo root, the shortest reproducible path is:

```bash
./scripts/check_extraction.sh
```

Focused variants:

```bash
./scripts/check_extraction.sh hax
./scripts/check_extraction.sh aeneas
```

That command:

- regenerates the focused `hax` outputs
- regenerates the focused composed `charon` + `aeneas` PCS output
- materializes repo-local Lean check packages under `target/extraction`
- compiles the generated Lean for both toolchains

It defaults to sibling checkouts:

- `../hax`
- `../aeneas`

and you can override paths with the environment variables documented below.

It covers two targets:

- the inner BaseFold replay verifier:
  `binius_iop::basefold_extract::verify_scripted_128b_ghash_extract`
- the composed replay verifier:
  `binius_verifier::pcs_extract::verify_scripted_128b_ghash_extract`

## Scope

These steps target the extraction-facing replay APIs, not the generic live verifier APIs.

That distinction matters:

- `aeneas` succeeds on the replay targets.
- `hax` succeeds on the replay targets.
- a naive whole-package `hax` run on `binius-verifier` still fails on the generic
  live verifier surface because of unsupported associated-type equality constraints in
  `crates/verifier/src/ring_switch.rs` and `crates/verifier/src/verify.rs`.

## Assumed Checkouts

Set these paths first:

```bash
export BINIUS_REPO=/path/to/binius64-pcs-kernel
export HAX_REPO=/path/to/hax
export AENEAS_REPO=/path/to/aeneas
export EXTRACTION_DIR="$BINIUS_REPO/target/extraction"
```

Example layout:

```text
$BINIUS_REPO   = .../binius64-pcs-kernel
$HAX_REPO      = .../hax
$AENEAS_REPO   = .../aeneas
$EXTRACTION_DIR = .../binius64-pcs-kernel/target/extraction
```

## Tool Prerequisites

### Rust

Run all extraction commands from the Binius repo root:

```bash
cd "$BINIUS_REPO"
```

The repo pins its own Rust toolchain in `rust-toolchain.toml`.

### `hax`

`cargo-hax` alone is not enough. The Lean backend also needs the OCaml `hax-engine` binary.

Build the engine from the `hax` checkout:

```bash
cd "$HAX_REPO/engine"
opam install --yes . --deps-only
opam exec -- dune build
```

Then point `cargo-hax` at the built engine:

```bash
export HAX_ENGINE_BINARY="$HAX_REPO/engine/_build/default/bin/native_driver.exe"
```

Optional convenience install:

```bash
cp "$HAX_ENGINE_BINARY" "$HOME/.cargo/bin/hax-engine"
```

Check the frontend binary:

```bash
cargo hax --version
```

### `aeneas` and `charon`

From the `aeneas` checkout:

```bash
cd "$AENEAS_REPO"
make setup-charon
make build
```

The binaries used below are:

```bash
export CHARON="$AENEAS_REPO/charon/charon/target/release/charon"
export AENEAS="$AENEAS_REPO/src/_build/default/main.exe"
```

## `hax` Reproduction

### 1. BaseFold replay target

```bash
cd "$BINIUS_REPO"

rm -rf "$EXTRACTION_DIR/hax-basefold-extract"
mkdir -p "$EXTRACTION_DIR/hax-basefold-extract"

HAX_ENGINE_BINARY="$HAX_ENGINE_BINARY" \
cargo hax -C -p binius-iop ';' \
  into \
  -i '-** +binius_iop::basefold_extract::verify_scripted_128b_ghash_extract' \
  --output-dir "$EXTRACTION_DIR/hax-basefold-extract" \
  lean
```

Expected artifact:

```text
$EXTRACTION_DIR/hax-basefold-extract/binius_iop.lean
```

### 2. Composed `RingSwitch + BaseFold / FRI` replay target

```bash
cd "$BINIUS_REPO"

rm -rf "$EXTRACTION_DIR/hax-pcs-extract"
mkdir -p "$EXTRACTION_DIR/hax-pcs-extract"

HAX_ENGINE_BINARY="$HAX_ENGINE_BINARY" \
cargo hax -C -p binius-verifier ';' \
  into \
  -i '-** +binius_verifier::pcs_extract::verify_scripted_128b_ghash_extract' \
  --output-dir "$EXTRACTION_DIR/hax-pcs-extract" \
  lean
```

Expected artifact:

```text
$EXTRACTION_DIR/hax-pcs-extract/binius_verifier.lean
```

### 3. What to check

The generated Lean should mention the replay targets:

```bash
rg 'verify_scripted_128b_ghash_extract|pcs_extract|basefold_extract' \
  "$EXTRACTION_DIR/hax-basefold-extract/binius_iop.lean" \
  "$EXTRACTION_DIR/hax-pcs-extract/binius_verifier.lean"
```

## `aeneas` Reproduction

`aeneas` is a two-stage pipeline:

1. `charon` extracts a focused `.llbc` file.
2. `aeneas` translates that `.llbc` file into Lean.

The commands below intentionally use:

- `--preset=aeneas`
- `--start-from ...` to focus the extraction
- `--no-dedup-serialized-ast` to produce the `.llbc` shape that worked reliably here

### 1. BaseFold replay target

#### Step 1: Charon

```bash
cd "$BINIUS_REPO"

rm -f "$EXTRACTION_DIR/binius_iop_basefold_extract.llbc"

"$CHARON" cargo \
  --preset=aeneas \
  --start-from crate::basefold_extract::verify_scripted_128b_ghash_extract \
  --no-dedup-serialized-ast \
  --dest-file "$EXTRACTION_DIR/binius_iop_basefold_extract.llbc" \
  -- \
  -p binius-iop
```

#### Step 2: Aeneas

```bash
rm -rf "$EXTRACTION_DIR/aeneas-basefold-extract"
mkdir -p "$EXTRACTION_DIR/aeneas-basefold-extract"

"$AENEAS" \
  -backend lean \
  -split-files \
  -dest "$EXTRACTION_DIR/aeneas-basefold-extract" \
  -namespace BiniusBasefoldExtract \
  "$EXTRACTION_DIR/binius_iop_basefold_extract.llbc"
```

Expected artifacts:

```text
$EXTRACTION_DIR/aeneas-basefold-extract/Types.lean
$EXTRACTION_DIR/aeneas-basefold-extract/Funs.lean
$EXTRACTION_DIR/aeneas-basefold-extract/TypesExternal_Template.lean
$EXTRACTION_DIR/aeneas-basefold-extract/FunsExternal_Template.lean
```

### 2. Composed `RingSwitch + BaseFold / FRI` replay target

#### Step 1: Charon

```bash
cd "$BINIUS_REPO"

rm -f "$EXTRACTION_DIR/binius_verifier_pcs_extract.llbc"

"$CHARON" cargo \
  --preset=aeneas \
  --start-from crate::pcs_extract::verify_scripted_128b_ghash_extract \
  --no-dedup-serialized-ast \
  --dest-file "$EXTRACTION_DIR/binius_verifier_pcs_extract.llbc" \
  -- \
  -p binius-verifier
```

#### Step 2: Aeneas

```bash
rm -rf "$EXTRACTION_DIR/aeneas-pcs-extract"
mkdir -p "$EXTRACTION_DIR/aeneas-pcs-extract"

"$AENEAS" \
  -backend lean \
  -split-files \
  -dest "$EXTRACTION_DIR/aeneas-pcs-extract" \
  -namespace BiniusPCSExtract \
  "$EXTRACTION_DIR/binius_verifier_pcs_extract.llbc"
```

Expected artifacts:

```text
$EXTRACTION_DIR/aeneas-pcs-extract/Types.lean
$EXTRACTION_DIR/aeneas-pcs-extract/Funs.lean
$EXTRACTION_DIR/aeneas-pcs-extract/TypesExternal_Template.lean
$EXTRACTION_DIR/aeneas-pcs-extract/FunsExternal_Template.lean
```

### 3. What to check

For the composed target:

```bash
rg 'verify_scripted_128b_ghash_extract|pcs_extract|ring_switch_extract' \
  "$EXTRACTION_DIR/aeneas-pcs-extract/Funs.lean" \
  "$EXTRACTION_DIR/aeneas-pcs-extract/Types.lean"
```

For the inner BaseFold target:

```bash
rg 'verify_scripted_128b_ghash_extract|basefold_extract' \
  "$EXTRACTION_DIR/aeneas-basefold-extract/Funs.lean" \
  "$EXTRACTION_DIR/aeneas-basefold-extract/Types.lean"
```

## Expected Runtime Notes

- The focused `charon` runs are fast, on the order of a few seconds.
- The focused composed `aeneas` run is moderate.
- The focused BaseFold `aeneas` run is much slower. On this machine it took about 706 seconds.

## Sanity Checks Before Extraction

These are not strictly part of the extraction commands, but they are useful if the tree changed:

```bash
cd "$BINIUS_REPO"
cargo test -p binius-verifier -- --nocapture
cargo test -p binius-prover --test pcs_extract_parity -- --nocapture
```

Those tests cover:

- the replay kernels themselves
- the composed transcript-parity harness

## Failure Modes

### `cargo hax` panics with `Os { code: 2, kind: NotFound }`

This usually means `hax-rust-engine` could not find the OCaml `hax-engine` binary.

Check:

```bash
echo "$HAX_ENGINE_BINARY"
test -x "$HAX_ENGINE_BINARY"
```

### Whole-package `hax` on `binius-verifier` fails

That is expected today. The generic live verifier surface still triggers:

```text
Unsupported equality constraints on associated types of parent trait
```

The replay extraction targets above are the intended `hax` entrypoints.

### `aeneas` rejects the `.llbc`

Regenerate the `.llbc` with:

- `--preset=aeneas`
- `--no-dedup-serialized-ast`

and make sure `charon` and `aeneas` come from the same checkout.

## Related Source Files

- `crates/iop/src/basefold_extract.rs`
- `crates/verifier/src/pcs_extract.rs`
- `crates/verifier/src/ring_switch_extract.rs`
