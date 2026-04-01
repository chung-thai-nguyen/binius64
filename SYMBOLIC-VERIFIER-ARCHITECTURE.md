# Architecture Memo: Symbolic Core for the Binius64 Verifier

## Goal

The long-term goal should be a verifier architecture with:

- a pure / functional interactive core
- explicit layering between protocol semantics, commitment verification, and Fiat-Shamir
- a first-class symbolic path suitable for recursion / circuit compilation
- clean extraction targets for both `hax` and `aeneas`
- no performance regression on the native streaming verifier path

The right target is not “extract the current transcript-backed verifier as-is.” The right target is to make the verifier semantics first-class, and treat transcript parsing, Merkle verification, and Fiat-Shamir as interpreters around that semantic core.

## Executive Summary

The best long-term architecture is:

1. Keep the verifier’s algebraic reductions as a pure interactive core.
2. Make `RingSwitch` and `BaseFold / FRI` explicit protocol layers, not behavior hidden inside a channel.
3. Move transcript reading, Merkle proof parsing, and Fiat-Shamir challenge derivation into outer interpreter layers.
4. Replace closure- and transcript-driven oracle APIs with typed protocol objects and typed relations.
5. Support two execution modes on the same semantics:
   - a streaming native interpreter for performance
   - a replay / symbolic interpreter for extraction, recursion, and testing

The current repo already points in this direction:

- the high-level verifier is almost a pure protocol core in `crates/verifier/src/verify.rs`
- the algebraic reductions are already generic over `IPVerifierChannel` in:
  - `crates/verifier/src/and_reduction/verifier.rs`
  - `crates/verifier/src/protocols/intmul/verify.rs`
  - `crates/verifier/src/protocols/shift/verify.rs`
  - `crates/verifier/src/ring_switch.rs`
- the current extraction modules prove that replayable typed verifier slices are practical:
  - `crates/iop/src/basefold_extract.rs`
  - `crates/verifier/src/ring_switch_extract.rs`
  - `crates/verifier/src/pcs_extract.rs`

The main architectural issue today is that the committed-oracle boundary is too coarse and too concrete at the same time:

- too coarse, because `IOPVerifierChannel::verify_oracle_relations` hides `RingSwitch + BaseFold / FRI` behind one call
- too concrete, because `BaseFold`, `FRI`, and `MerkleTreeScheme` still read directly from `VerifierTranscript`, `TranscriptReader<B>`, and `Buf`

## 1. Semantic Core Boundary

### Recommendation

The semantic core boundary should be:

- verifier setup / plan data
- pure interactive reductions
- pure committed-oracle opening semantics
- final consistency checks

It should exclude:

- transcript byte parsing
- Merkle proof byte parsing
- Fiat-Shamir hashing and transcript state mutation
- serialization / deserialization details
- concrete proof transport

Concretely, the semantic core should contain:

- `AndCheck`, `IntMul`, `Shift`, and `RingSwitch`
- `BaseFold` fold-phase semantics
- `FRI` query-phase semantics
- final consistency checks linking `RingSwitch` and `BaseFold / FRI`

It should not directly contain:

- `VerifierTranscript`
- `TranscriptReader<B>`
- `Buf`
- `MerkleTreeScheme::verify_*` methods that read from transcript readers

### Why this is the right boundary in the current codebase

The current `Verifier::verify_iop` in `crates/verifier/src/verify.rs` is already very close to the desired core boundary. It composes:

- `verify_intmul_reduction`
- `verify_bitand_reduction`
- `shift::verify`
- `ring_switch::verify`
- then a PCS opening check

That is already the semantic spine of verification.

The reductions below it are also already close to ideal:

- `crates/verifier/src/and_reduction/verifier.rs` is generic over `IPVerifierChannel`
- `crates/verifier/src/protocols/intmul/verify.rs` is generic over `IPVerifierChannel`
- `crates/verifier/src/protocols/shift/verify.rs` is generic over `IPVerifierChannel`
- `crates/verifier/src/ring_switch.rs` is generic over `IPVerifierChannel`

The main impurity starts at the committed-oracle layer:

- `crates/iop/src/basefold.rs`
- `crates/iop/src/fri/verify.rs`
- `crates/iop/src/merkle_tree/merkle_tree_vcs.rs`

These modules mix semantic verification with transcript-driven proof transport.

## 2. Layering: RingSwitch, BaseFold / FRI, Transcript, Merkle, Fiat-Shamir

### Recommended layering

#### Layer A: Static verifier plan

This layer contains precomputed protocol parameters and tables:

- constraint-system-derived verifier metadata
- FRI arity schedule
- oracle specs
- twiddle tables or domain context handles
- Merkle layer schedule

Today, `crates/verifier/src/verify.rs` and `crates/iop/src/basefold_compiler.rs` already partially play this role.

#### Layer B: Pure interactive verifier core

This layer is the protocol semantics.

It should cover:

- `AndCheck`
- `IntMul`
- `Shift`
- `RingSwitch`
- `BaseFold` fold semantics
- `FRI` query semantics
- final consistency predicates

This layer should be deterministic given:

- public inputs
- verifier plan
- typed prover messages
- typed random challenges
- typed oracle opening artifacts

This is the layer that should be extractable to Lean and interpretable as a circuit.

#### Layer C: Oracle commitment / opening interpreter

This layer should interpret the committed-oracle part of the protocol:

- receive oracle commitments
- verify Merkle layers / openings
- expose typed opening artifacts to Layer B

This is where BaseFold / FRI should be split:

- the arithmetic fold/query logic belongs in Layer B
- commitment and opening verification belongs here

#### Layer D: Fiat-Shamir / transcript interpreter

This layer should be responsible for:

- observing public inputs and prover messages
- deriving challenges
- parsing decommitment streams
- producing typed artifacts for Layer C / Layer B

This layer should be the only place that knows about:

- `VerifierTranscript`
- `TranscriptReader<B>`
- `Buf`
- byte serialization

#### Layer E: Alternate interpreters

On top of the same semantic core, support:

- native streaming verifier interpreter
- replay interpreter
- symbolic / circuit interpreter
- extraction-oriented interpreter
- size-estimation interpreter

The current repo already has partial evidence for this pattern:

- `crates/iop/src/naive_channel.rs`
- `crates/iop/src/size_tracking_channel.rs`
- `crates/iop/src/basefold_extract.rs`
- `crates/verifier/src/ring_switch_extract.rs`
- `crates/verifier/src/pcs_extract.rs`

### Where RingSwitch belongs

`RingSwitch` belongs in the semantic core, not in the transcript/Merkle layer.

Reason:

- `crates/verifier/src/ring_switch.rs` is already a pure public-coin protocol over `IPVerifierChannel`
- it computes the reduction from witness evaluation claims to the BaseFold claim
- it also defines the transparent relation checked after BaseFold via `eval_rs_eq`

So the natural layering is:

`Shift -> RingSwitch -> BaseFold fold core -> FRI query core -> final consistency`

not:

`Shift -> opaque PCS channel`

## 3. Abstractions to Replace the Current Verifier / Channel Boundaries

### A. Keep a small public-coin interaction interface

The existing `IPVerifierChannel` is close to the right abstraction for the algebraic reductions. The main change should be architectural, not conceptual:

- keep the small receive / sample / observe / assert surface
- do not make transcript-backed implementations the semantic boundary
- treat transcript-backed execution as one interpreter

The current trait in `crates/ip/src/channel.rs` is a good starting point.

### B. Remove `IOPVerifierChannel::verify_oracle_relations`

This is the biggest boundary change.

`crates/iop/src/channel.rs` currently hides too much behind:

- `recv_oracle`
- `verify_oracle_relations`

Problems with the current design:

- it collapses `BaseFold` invocation, FRI query verification, transparent relation evaluation, and final consistency into one method
- it uses `Box<dyn Fn(&[Elem]) -> Elem>` for transparent relations
- it prevents the top-level verifier from explicitly composing `RingSwitch` with the PCS opening slice

It should be replaced with explicit typed layers, for example:

- `CommitmentHandle`
- `OracleOpeningClaim`
- `OracleOpeningResult`
- `TransparentRelation`

The top-level verifier should assemble the PCS relation explicitly instead of handing a boxed closure to a channel.

### C. Replace boxed transparent closures with typed relations

Current issue:

- `crates/iop/src/channel.rs` defines `TransparentEvalFn = Box<dyn Fn(&[Elem]) -> Elem>`
- `OracleLinearRelation` stores a boxed closure

This is not a good long-term boundary for:

- extraction
- symbolic execution
- circuit compilation
- discoverable protocol structure

Replace it with typed relations such as:

- `RingSwitchEqualityRelation`
- `TransparentPolynomialRelation`
- or a small enum / trait hierarchy with concrete data fields

The `RingSwitch` relation is already an explicit semantic object in practice:

- the data comes from `crates/verifier/src/ring_switch.rs`
- the replay path makes this concrete in `crates/verifier/src/pcs_extract.rs`

### D. Split BaseFold / FRI into semantic core and proof interpreter

Current issue:

- `crates/iop/src/basefold.rs` reads sumcheck rounds and challenges directly from `VerifierTranscript`
- `crates/iop/src/fri/verify.rs` reads query proof data directly from `TranscriptReader<B>`
- `crates/iop/src/merkle_tree/merkle_tree_vcs.rs` requires `TranscriptReader<B>` in `verify_vector` and `verify_opening`

The replacement should be:

- `basefold_core`
  - fold-phase transitions
  - reduced output
  - final consistency
- `fri_query_core`
  - query consistency logic over typed openings / layers / terminal codeword
- `merkle_verifier`
  - verifies typed Merkle proof objects
- `transcript_parser`
  - parses bytes into typed proof objects

The current replay modules show the right shape for the typed proof layer:

- `ExtractProofOracle` in `crates/iop/src/basefold_extract.rs`
- `ExtractRingSwitchChannel` in `crates/verifier/src/ring_switch_extract.rs`

Those modules should not remain the final architecture, but they do identify the right seam.

### E. Introduce a first-class verifier plan

`crates/iop/src/basefold_compiler.rs` already precomputes:

- oracle specs
- FRI params
- layer schedule inputs

This should evolve into a first-class verifier plan object that separates:

- static protocol configuration
- dynamic proof interaction

That plan should be shared by:

- the native streaming verifier
- replay extraction paths
- circuit compilation

## 4. How to Preserve Performance and Modularity

The key is to share semantics without forcing a single proof representation.

### A. Keep streaming as a first-class interpreter

The production verifier should remain streaming.

Do not force the native path to materialize the whole proof into replay structs.

Instead:

- the semantic core should be request-driven
- the native interpreter should satisfy those requests directly from transcript / Merkle state
- the replay interpreter should satisfy the same requests from typed stored artifacts

This preserves the main performance win of the current architecture: low buffering and straightforward verifier flow.

### B. Separate reference kernels from optimized kernels

Hot arithmetic should have:

- one reference, extractor-friendly implementation
- one optimized native implementation

This especially matters in the FRI query slice, where current code uses:

- `fold_chunk`
- `fold_interleaved_chunk`
- `GenericOnTheFly`
- `NeighborsLastSingleThread`

from:

- `crates/iop/src/fri/fold.rs`
- `crates/iop/src/fri/verify.rs`

The semantic interface should not depend on packed-field or transcript machinery, but native interpreters should still be free to call optimized folding kernels internally.

### C. Keep setup and proof-size tooling as separate interpreters

The repo already demonstrates that alternate interpreters are useful:

- `crates/iop/src/naive_channel.rs`
- `crates/iop/src/size_tracking_channel.rs`

That pattern should be extended, not replaced.

### D. Avoid dynamic dispatch and hidden closures in hot paths

Do not put `Box<dyn Fn>` or trait objects in performance-sensitive protocol code.

Prefer:

- concrete relation structs
- enums
- generic functions over concrete relation types

### E. Make challenge order explicit

The current verifier repeatedly uses `reverse()` to recover evaluation-point order from transcript order:

- `crates/verifier/src/protocols/shift/verify.rs`
- `crates/verifier/src/and_reduction/verifier.rs`
- `crates/iop/src/basefold_channel.rs`
- `crates/iop/src/basefold.rs`
- `crates/verifier/src/pcs_extract.rs`

That should be replaced by explicit types or conventions, such as:

- `ChallengeOrder::Protocol`
- `EvaluationPoint::LowToHigh`

Implicit reversal is bad for:

- readability
- symbolic execution
- Lean proofs
- circuit reproducibility

## 5. Migration Plan

### Phase 1: Freeze the semantic outputs

Before major refactoring, standardize the key typed outputs:

- shift output
- ring-switch output
- BaseFold reduced output
- FRI query result
- final PCS opening result

The current outputs in:

- `crates/verifier/src/ring_switch.rs`
- `crates/iop/src/basefold.rs`
- `crates/verifier/src/pcs_extract.rs`

are enough to start this normalization.

### Phase 2: Lift the verifier spine into an explicit semantic core

Refactor the logic currently embodied in `Verifier::verify_iop` into a core module that:

- composes the reductions explicitly
- no longer treats PCS opening as one opaque channel method

Target:

- the top-level verifier still looks like current `crates/verifier/src/verify.rs`
- but the semantic composition lives in a core layer with no transcript-specific code

### Phase 3: Split `IOPVerifierChannel`

Replace `verify_oracle_relations` with explicit pieces:

- commitment receipt
- opening claim construction
- BaseFold / FRI semantic verification
- transparent relation evaluation
- final consistency

The top-level verifier should explicitly compose `RingSwitch` with the PCS opening slice.

### Phase 4: Split BaseFold / FRI along semantic vs interpreter lines

Break today’s `BaseFold` / `FRI` implementation into:

- `basefold_fold_core`
- `fri_query_core`
- `merkle_opening_interpreter`
- `transcript_parser`

This is the highest-leverage refactor for recursion and extraction.

### Phase 5: Promote replay extractors into official interpreters

The current replay modules:

- `crates/iop/src/basefold_extract.rs`
- `crates/verifier/src/ring_switch_extract.rs`
- `crates/verifier/src/pcs_extract.rs`

should become official alternate interpreters of the same semantic core, not permanently duplicated verifier logic.

### Phase 6: Add a symbolic / circuit interpreter

Once the semantic core is explicit, add an interpreter that:

- treats prover messages as symbolic witness values
- treats Fiat-Shamir challenges as symbolic outputs of a transcript hash gadget
- treats Merkle checks as hash-path constraints

This is the natural recursion target.

### Phase 7: Retire legacy boundaries

After parity and performance benchmarks are stable:

- de-emphasize or remove `IOPVerifierChannel::verify_oracle_relations`
- move transcript-backed implementations behind adapter modules
- keep the semantic core as the canonical protocol definition

## 6. Risks and Anti-Patterns to Avoid

### Anti-pattern 1: Keep separate live and extract verifiers forever

The current replay modules are useful prototypes, but long-term duplicated logic is dangerous.

The goal should be:

- one semantic core
- many interpreters

not:

- one native verifier
- one replay verifier
- one circuit verifier
- one Lean verifier

all hand-maintained separately

### Anti-pattern 2: Keep transcript parsing in the semantic core

Avoid any core API that requires:

- `VerifierTranscript`
- `TranscriptReader<B>`
- `Buf`

Those are interpreter concerns.

### Anti-pattern 3: Hide protocol layering inside channels

`RingSwitch + BaseFold / FRI` should be explicit protocol composition, not a black box inside an oracle channel.

The current `verify_oracle_relations` design hides exactly the slice that needs to become symbolic.

### Anti-pattern 4: Overfit the core to extraction tools

Do not design the semantic core around the current limitations of `hax` or `aeneas`.

Instead:

- make the core explicit, typed, and pure
- keep optimized native interpreters around it
- let extraction target the replay / symbolic interpreters

### Anti-pattern 5: Bake packed-field / NTT implementation details into the core boundary

Packed kernels and domain-context machinery are important for performance, but they are not the semantic boundary.

Current hot-path machinery in:

- `crates/iop/src/fri/fold.rs`
- `crates/iop/src/fri/verify.rs`
- `crates/verifier/src/ring_switch.rs`

should remain available to native interpreters, not define the core API.

### Anti-pattern 6: Use boxed closures for algebraic relations

The closure-based relation boundary in `crates/iop/src/channel.rs` is convenient short-term, but it is not a good foundation for:

- symbolic execution
- proof extraction
- circuit compilation
- proof-oriented documentation

### Anti-pattern 7: Treat challenge ordering as implicit protocol folklore

Every challenge ordering convention should be made explicit in data types or protocol documentation. Repeated ad hoc `reverse()` calls are a sign that this part of the protocol boundary is underspecified.

## Concrete Long-Term Target

The cleanest end state is:

- a `VerifierPlan`
- a pure `VerifierCore`
- explicit `RingSwitchCore`
- explicit `BaseFoldCore`
- explicit `FriQueryCore`
- typed `TransparentRelation` objects
- interpreter modules for:
  - transcript + Fiat-Shamir
  - Merkle / VCS
  - replay / extraction
  - symbolic / circuit
  - proof-size estimation

In that design:

- the native verifier remains streaming and fast
- `hax` and `aeneas` target the replay or symbolic interpreter cleanly
- recursion targets the same semantic core rather than a duplicate verifier
- the top-level verifier composition is explicit and modular

## Bottom Line

The best long-term architecture is not “make the current verifier slightly easier to extract.” It is:

- keep the existing reduction-style verifier core
- split committed-oracle verification into explicit semantic and interpreter layers
- make transcript / Merkle / Fiat-Shamir outer adapters
- use replay interpreters as extraction and circuit-compilation entrypoints
- preserve native streaming performance with specialized interpreters and kernels

The current codebase already contains the beginnings of this architecture. The right move is to promote that structure into the main design rather than continue adding extraction-specific side paths around a transcript-coupled PCS boundary.
