#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/check_extraction.sh [all|hax|aeneas]

Defaults:
  all      regenerate and compile-check both Hax and Aeneas targets
  hax      regenerate and compile-check only Hax targets
  aeneas   regenerate and compile-check only Aeneas targets

Environment overrides:
  BINIUS_REPO
  HAX_REPO
  AENEAS_REPO
  EXTRACTION_DIR
  HAX_ENGINE_BINARY
  CHARON
  AENEAS
EOF
}

MODE="${1:-all}"
if [[ $# -gt 1 ]]; then
  usage
  exit 1
fi

case "$MODE" in
  all|hax|aeneas) ;;
  *)
    usage
    exit 1
    ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PARENT="$(cd "$ROOT/.." && pwd)"

BINIUS_REPO="${BINIUS_REPO:-$ROOT}"
HAX_REPO="${HAX_REPO:-$PARENT/hax}"
AENEAS_REPO="${AENEAS_REPO:-$PARENT/aeneas}"
EXTRACTION_DIR="${EXTRACTION_DIR:-$BINIUS_REPO/target/extraction}"

if [[ -z "${HAX_ENGINE_BINARY:-}" ]]; then
  if [[ -x "$HOME/.cargo/bin/hax-engine" ]]; then
    HAX_ENGINE_BINARY="$HOME/.cargo/bin/hax-engine"
  elif [[ -x "$HAX_REPO/engine/_build/default/bin/native_driver.exe" ]]; then
    HAX_ENGINE_BINARY="$HAX_REPO/engine/_build/default/bin/native_driver.exe"
  else
    echo "Missing hax-engine; set HAX_ENGINE_BINARY or build it under $HAX_REPO/engine" >&2
    exit 1
  fi
fi

CHARON="${CHARON:-$AENEAS_REPO/charon/charon/target/release/charon}"
if [[ -z "${AENEAS:-}" ]]; then
  if [[ -x "$AENEAS_REPO/src/_build/default/main.exe" ]]; then
    AENEAS="$AENEAS_REPO/src/_build/default/main.exe"
  elif [[ -x "$AENEAS_REPO/target/release/aeneas" ]]; then
    AENEAS="$AENEAS_REPO/target/release/aeneas"
  else
    echo "Missing aeneas binary; set AENEAS or build it under $AENEAS_REPO" >&2
    exit 1
  fi
fi

for path in "$BINIUS_REPO" "$HAX_REPO" "$AENEAS_REPO"; do
  [[ -d "$path" ]] || { echo "Missing directory: $path" >&2; exit 1; }
done

for path in "$HAX_ENGINE_BINARY" "$CHARON" "$AENEAS"; do
  [[ -x "$path" ]] || { echo "Missing executable: $path" >&2; exit 1; }
done

mkdir -p "$EXTRACTION_DIR"

log() {
  printf '\n==> %s\n' "$*"
}

run_extract_surface_checks() {
  log "Checking extract authoring surface"
  python3 "$ROOT/scripts/extraction-check/check_extract_surface.py"
}

retry() {
  local attempts="$1"
  shift
  local attempt=1
  while true; do
    if "$@"; then
      return 0
    fi
    if (( attempt >= attempts )); then
      return 1
    fi
    printf 'retrying (%d/%d)\n' "$attempt" "$attempts" >&2
    attempt=$((attempt + 1))
    sleep 2
  done
}

prepend_imports() {
  local file="$1"
  local imports="$2"
  python3 - "$file" "$imports" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
imports = sys.argv[2]
text = path.read_text()
if imports in text:
    raise SystemExit(0)
needle = "import Hax\n"
if needle not in text:
    raise SystemExit(f"missing import Hax in {path}")
path.write_text(text.replace(needle, needle + imports, 1))
PY
}

patch_hax_singleton_literals() {
  local file="$1"
  python3 - "$file" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
old = """(alloc.slice.Impl.into_vec
      binius_field.ghash.BinaryField128bGhash
      alloc.alloc.Global
      (← (rust_primitives.unsize
        (RustArray.ofVec #v[(← (binius_field.ghash.Impl.new (1 : u128)))]))))"""
new = """(alloc.vec.from_elem
      binius_field.ghash.BinaryField128bGhash
      (← (binius_field.ghash.Impl.new (1 : u128)))
      (1 : usize))"""
path.write_text(text.replace(old, new))
PY
}

write_hax_check_package() {
  local dir="$EXTRACTION_DIR/check-hax-pcs"
  mkdir -p "$dir"

  cp "$HAX_REPO/hax-lib/proof-libs/lean/lean-toolchain" "$dir/lean-toolchain"
  cp "$ROOT/scripts/extraction-check/hax/BiniusField.lean" "$dir/BiniusField.lean"
  cp "$ROOT/scripts/extraction-check/hax/BiniusHaxCompat.lean" "$dir/BiniusHaxCompat.lean"
  cp "$EXTRACTION_DIR/hax-basefold-extract/binius_iop.lean" "$dir/BiniusIop.lean"
  cp "$EXTRACTION_DIR/hax-pcs-extract/binius_verifier.lean" "$dir/BiniusVerifier.lean"

  prepend_imports "$dir/BiniusIop.lean" $'import BiniusField\nimport BiniusHaxCompat\n'
  prepend_imports "$dir/BiniusVerifier.lean" $'import BiniusField\nimport BiniusHaxCompat\nimport BiniusIop\n'
  patch_hax_singleton_literals "$dir/BiniusIop.lean"
  patch_hax_singleton_literals "$dir/BiniusVerifier.lean"

  cat > "$dir/lakefile.lean" <<EOF
import Lake
open Lake DSL

require Hax from "$HAX_REPO/hax-lib/proof-libs/lean"

package «check-hax-pcs» {}

@[default_target] lean_lib «BiniusField» {}
@[default_target] lean_lib «BiniusHaxCompat» {}
@[default_target] lean_lib «BiniusIop» {}
@[default_target] lean_lib «BiniusVerifier» {}
EOF

  cat > "$dir/CheckHaxPcs.lean" <<'EOF'
import BiniusVerifier
EOF

  log "Building Hax check package"
  retry 3 bash -lc "cd \"$dir\" && ~/.elan/bin/lake build BiniusVerifier"
}

write_aeneas_check_package() {
  local module_name="$1"
  local src_dir="$2"
  local dir="$3"

  mkdir -p "$dir/$module_name"

  cp "$src_dir/Types.lean" "$dir/$module_name/Types.lean"
  cp "$src_dir/Funs.lean" "$dir/$module_name/Funs.lean"
  cp "$src_dir/TypesExternal_Template.lean" "$dir/$module_name/TypesExternal.lean"
  cp "$src_dir/FunsExternal_Template.lean" "$dir/$module_name/FunsExternal.lean"

  cat > "$dir/$module_name.lean" <<EOF
import ${module_name}.Funs
EOF
}

build_aeneas_module_tree() {
  local dir="$1"
  local module_name="$2"
  local rel
  for rel in \
    "$module_name/TypesExternal.lean" \
    "$module_name/Types.lean" \
    "$module_name/FunsExternal.lean" \
    "$module_name/Funs.lean" \
    "$module_name.lean"
  do
    local src="$dir/$rel"
    local base="${src%.lean}"
    (
      cd "$AENEAS_REPO/backends/lean" &&
      ~/.elan/bin/lake env bash -lc \
        "LEAN_PATH=\"$dir:\$LEAN_PATH\" lean -R \"$dir\" \"$src\" -o \"$base.olean\" -i \"$base.ilean\" -c \"$base.c\""
    )
  done
}

run_hax() {
  run_extract_surface_checks

  log "Generating Hax BaseFold extract"
  (
    cd "$BINIUS_REPO"
    rm -rf "$EXTRACTION_DIR/hax-basefold-extract"
    mkdir -p "$EXTRACTION_DIR/hax-basefold-extract"
    HAX_ENGINE_BINARY="$HAX_ENGINE_BINARY" \
      cargo hax -C -p binius-iop ';' \
      into \
      -i '-** +binius_iop::basefold_extract::verify_statement_transcript_128b_ghash_extract +binius_iop::basefold_extract::verify_authenticated_statement_transcript_128b_ghash_extract +binius_iop::basefold_extract::finalize_authenticated_128b_ghash_extract +binius_iop::basefold_extract::ExtractBasefoldStatement +binius_iop::basefold_extract::ExtractBasefoldProofView +binius_iop::basefold_extract::ExtractBasefoldSamplingView +binius_iop::basefold_extract::ExtractBasefoldTranscriptView +binius_iop::basefold_extract::ExtractSamplingTrace +binius_iop::basefold_extract::ExtractOpenedLinearRelation +binius_iop::basefold_extract::ExtractOpenedLinearRelationWithSampling +binius_iop::basefold_extract::ExtractReducedOutput +binius_iop::basefold_extract::ExtractAuthenticatedLinearRelationOpening +binius_iop::basefold::ReducedOutput +binius_iop::basefold::SamplingTrace +binius_iop::basefold::OpenedLinearRelation +binius_iop::basefold::OpenedLinearRelationWithSampling +binius_iop::basefold::query_point_from_challenges +binius_iop::basefold::opened_linear_relation_from_challenges' \
      --output-dir "$EXTRACTION_DIR/hax-basefold-extract" \
      lean
  )

  log "Generating Hax PCS extract"
  (
    cd "$BINIUS_REPO"
    rm -rf "$EXTRACTION_DIR/hax-pcs-extract"
    mkdir -p "$EXTRACTION_DIR/hax-pcs-extract"
    HAX_ENGINE_BINARY="$HAX_ENGINE_BINARY" \
      cargo hax -C -p binius-verifier ';' \
      into \
      -i '-** +binius_verifier::pcs_extract::verify_statement_transcript_128b_ghash_extract +binius_verifier::pcs_extract::verify_authenticated_statement_transcript_128b_ghash_extract +binius_verifier::pcs_extract::finalize_authenticated_128b_ghash_extract +binius_verifier::pcs_extract::ExtractPcsStatement +binius_verifier::pcs_extract::ExtractPcsTranscriptView +binius_verifier::pcs_extract::ExtractPcsOpeningOutput +binius_verifier::pcs_extract::ExtractAuthenticatedPcsOpening +binius_verifier::ring_switch_extract::ExtractRingSwitchStatement +binius_verifier::ring_switch_extract::ExtractRingSwitchProofView +binius_verifier::ring_switch_extract::ExtractRingSwitchSamplingView +binius_verifier::ring_switch_extract::ExtractRingSwitchTranscriptView' \
      --output-dir "$EXTRACTION_DIR/hax-pcs-extract" \
      lean
  )

  write_hax_check_package
}

run_aeneas() {
  run_extract_surface_checks

  log "Generating Aeneas PCS LLBC"
  (
    cd "$BINIUS_REPO"
    rm -f "$EXTRACTION_DIR/binius_verifier_pcs_extract.llbc"
    "$CHARON" cargo \
      --preset=aeneas \
      --start-from crate::pcs_extract::verify_statement_transcript_128b_ghash_extract \
      --no-dedup-serialized-ast \
      --dest-file "$EXTRACTION_DIR/binius_verifier_pcs_extract.llbc" \
      -- \
      -p binius-verifier
  )

  log "Generating Aeneas PCS Lean"
  (
    cd "$BINIUS_REPO"
    rm -rf "$EXTRACTION_DIR/aeneas-pcs-extract"
    mkdir -p "$EXTRACTION_DIR/aeneas-pcs-extract"
    "$AENEAS" \
      -backend lean \
      -split-files \
      -dest "$EXTRACTION_DIR/aeneas-pcs-extract" \
      -namespace BiniusPCSExtract \
      "$EXTRACTION_DIR/binius_verifier_pcs_extract.llbc"
  )

  write_aeneas_check_package \
    "BiniusVerifierPcsExtract" \
    "$EXTRACTION_DIR/aeneas-pcs-extract" \
    "$EXTRACTION_DIR/check-aeneas-pcs"

  log "Building Aeneas PCS check package"
  retry 3 build_aeneas_module_tree \
    "$EXTRACTION_DIR/check-aeneas-pcs" \
    "BiniusVerifierPcsExtract"
}

case "$MODE" in
  all)
    run_hax
    run_aeneas
    ;;
  hax)
    run_hax
    ;;
  aeneas)
    run_aeneas
    ;;
esac

log "Done"
printf 'Artifacts under %s\n' "$EXTRACTION_DIR"
