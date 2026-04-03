import os
import re

files = [
    "crates/iop/src/basefold_extract.rs",
    "crates/verifier/src/ring_switch_extract.rs",
    "crates/verifier/src/pcs_extract.rs",
    "scripts/check_extraction.sh",
    "EXTRACTION-REPRO.md",
    "scripts/extraction-check/check_extract_surface.py",
]

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

for file_path in files:
    if not os.path.exists(file_path):
        continue
    with open(file_path, "r") as f:
        content = f.read()
    
    # We will do this manually for Rust files via better parsing or simple replacements.
    # Just to check, let's see how many structs we have
    structs = re.findall(r'pub struct (\w+)', content)
    print(f"{file_path}: {structs}")

