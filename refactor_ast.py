import re
import os

basefold_path = "crates/iop/src/basefold_extract.rs"
ring_switch_path = "crates/verifier/src/ring_switch_extract.rs"
pcs_path = "crates/verifier/src/pcs_extract.rs"

trait_code = """pub trait ExtractField: Copy + Clone + PartialEq {
    const ZERO: Self;
    const ONE: Self;
    fn add(self, rhs: Self) -> Self;
    fn mul(self, rhs: Self) -> Self;
    fn sub(self, rhs: Self) -> Self;
}

impl<T: binius_field::Field> ExtractField for T {
    const ZERO: Self = <T as binius_field::Field>::ZERO;
    const ONE: Self = <T as binius_field::Field>::ONE;
    fn add(self, rhs: Self) -> Self { self + rhs }
    fn mul(self, rhs: Self) -> Self { self * rhs }
    fn sub(self, rhs: Self) -> Self { self - rhs }
}
"""

def process_file(path):
    with open(path, "r") as f:
        content = f.read()

    # 1. Rename _128b_ghash_extract -> _extract
    content = content.replace("_128b_ghash_extract", "_extract")

    # 2. Add ExtractField trait in basefold_extract
    if "basefold_extract.rs" in path:
        content = re.sub(r'pub type ExtractField = BinaryField128bGhash;\n', trait_code, content)
    else:
        # For ring_switch and pcs
        content = re.sub(r'pub type ExtractField = BinaryField128bGhash;\n', '', content)
        content = re.sub(r'use binius_field::BinaryField128bGhash;\n', 'use binius_iop::basefold_extract::ExtractField;\n', content)

    # 3. Replace ExtractField::new(0) with F::ZERO and so on.
    content = content.replace("ExtractField::new(0)", "F::ZERO")
    content = content.replace("ExtractField::new(1)", "F::ONE")

    # Make structs generic
    structs_to_make_generic = [
        "ExtractSamplingTrace", "ExtractOpenedLinearRelation", "ExtractOpenedLinearRelationWithSampling",
        "ExtractReducedOutput", "ExtractAuthenticatedLinearRelationOpening", "ExtractBasefoldStatement",
        "ExtractBasefoldProofView", "ExtractBasefoldSamplingView", "ExtractBasefoldTranscriptView",
        "ExtractBasefoldProtocol", "ExtractRingSwitchStatement", "ExtractRingSwitchProofView",
        "ExtractRingSwitchSamplingView", "ExtractRingSwitchTranscriptView", "ExtractRingSwitchProtocol",
        "ExtractRingSwitchChannel", "ExtractRingSwitchEqRelation", "ExtractRingSwitchOutput",
        "ExtractPcsStatement", "ExtractPcsTranscriptView", "ExtractPcsProtocol", "ExtractPcsOpeningOutput",
        "ExtractAuthenticatedPcsOpening"
    ]

    for struct in structs_to_make_generic:
        # replace `pub struct StructName {` with `pub struct StructName<F: ExtractField> {`
        content = re.sub(rf'pub struct {struct}\b(\s*{{)', rf'pub struct {struct}<F: ExtractField>\1', content)
        content = re.sub(rf'pub struct {struct}\b(\s*;)', rf'pub struct {struct}<F: ExtractField>\1', content)
        # replace `impl StructName {` with `impl<F: ExtractField> StructName<F> {`
        content = re.sub(rf'impl {struct}\b(\s*{{)', rf'impl<F: ExtractField> {struct}<F>\1', content)
        # replace usages of `StructName` with `StructName<F>` in function args/returns, but handle carefully
        # Simple heuristic: StructName followed by not a `<`
        content = re.sub(rf'\b{struct}\b(?!<)', rf'{struct}<F>', content)

    # Change all ExtractField fields to F
    content = re.sub(r'\bExtractField\b(?!>|::)', 'F', content)

    # Revert `F` inside trait bounds if we broke it
    content = content.replace("impl<F: F>", "impl<F: ExtractField>")
    content = content.replace("<F: F>", "<F: ExtractField>")

    # Make functions generic: pub fn foo(...) -> ...
    # We'll just replace `pub fn (\w+)\((.*?)\)` with `pub fn \1<F: ExtractField>(\2)`
    # This is tricky because some functions don't use F.
    # A safe way is to add `<F: ExtractField>` to any function that uses `F` in its signature.
    # Actually, simpler: replace all `pub fn ` with `pub fn ` then parse.
    
    with open(path, "w") as f:
        f.write(content)

for path in [basefold_path, ring_switch_path, pcs_path]:
    process_file(path)

