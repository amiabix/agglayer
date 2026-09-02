use std::{
    env, fs,
    path::{Path, PathBuf},
};

use semver::Version;
use toml::Value;

fn main() {
    generate_program_version();
    configure_zisk_vadcop_key();
}

fn generate_program_version() {
    println!("cargo:rerun-if-changed=Cargo.toml");
    let cargo_toml_path = Path::new("../pessimistic-proof-program/Cargo.toml");
    println!("cargo:rerun-if-changed={}", cargo_toml_path.display());
    let cargo_toml = fs::read_to_string(cargo_toml_path).expect("Failed to read Cargo.toml");
    let parsed_toml: Value = toml::from_str(&cargo_toml).expect("Failed to parse Cargo.toml");

    let version: Version = parsed_toml
        .get("package")
        .and_then(|pkg| pkg.get("version"))
        .and_then(|v| {
            v.as_str()
                .map(Version::parse)
                .transpose()
                .expect("Unable to extract version")
        })
        .expect("Unable to extract version");

    let major_version = version.major.to_string();
    let dest_path = Path::new(&env::var_os("OUT_DIR").expect("OUT_DIR not set")).join("version.rs");
    fs::write(
        &dest_path,
        format!("pub const PESSIMISTIC_PROOF_PROGRAM_VERSION: u32 = {major_version};\n"),
    )
    .expect("Failed to write pessimistic-proof-core version.rs");
}

fn configure_zisk_vadcop_key() {
    println!("cargo:rerun-if-env-changed=ZISK_VADCOP_VK_PATH");

    if env::var_os("CARGO_FEATURE_ZISK").is_none() {
        return;
    }

    let path = env::var_os("ZISK_VADCOP_VK_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("HOME").map(|home| {
                PathBuf::from(home).join(
                    ".zisk/provingKey/zisk/vadcop_final_compressed/vadcop_final_compressed.verkey.bin",
                )
            })
        })
        .expect("set ZISK_VADCOP_VK_PATH to the compressed VADCOP verifier key");

    let metadata = fs::metadata(&path).expect("failed to read the compressed VADCOP verifier key");
    assert_eq!(
        metadata.len(),
        32,
        "the compressed VADCOP verifier key must be 32 bytes"
    );

    println!("cargo:rerun-if-changed={}", path.display());
    let output = Path::new(&env::var_os("OUT_DIR").expect("OUT_DIR not set"))
        .join("zisk_vadcop_vk.bin");
    fs::copy(path, output).expect("failed to copy the compressed VADCOP verifier key");
}
