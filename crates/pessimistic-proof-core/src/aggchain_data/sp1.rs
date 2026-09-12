use std::borrow::Borrow;

use bincode::Options;
use slop_algebra::{AbstractField, PrimeField32};
use sp1_primitives::SP1Field;
use sp1_recursion_executor::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS};
use sp1_verifier::{
    compressed::{CompressedError, SP1CompressedVerifier},
    SP1Proof,
};

use super::Vkey;

#[cfg(all(target_os = "zkvm", feature = "sp1"))]
compile_error!("zisk-sp1 requires disabling the core crate's default sp1 feature");

#[derive(Debug, thiserror::Error)]
pub enum Sp1AggchainProofError {
    #[error("invalid SP1 proof encoding: {0}")]
    Decode(#[from] bincode::Error),
    #[error("SP1 proof bytes are not the canonical encoding")]
    NoncanonicalEncoding,
    #[error("SP1 recursion verifying-key Merkle index is out of range")]
    MerkleIndex,
    #[error("expected an SP1 compressed proof")]
    ProofType,
    #[error("SP1 program key contains a noncanonical field element")]
    ProgramKey,
    #[error("invalid SP1 recursion public values length")]
    PublicValuesLength,
    #[error("SP1 public values do not match the certificate")]
    PublicValues,
    #[error("SP1 guest did not exit successfully")]
    ExitCode,
    #[error("SP1 compressed proof verification failed: {0}")]
    Verification(#[from] CompressedError),
}

fn merkle_index_is_in_range(index: usize, path_len: usize) -> bool {
    path_len >= usize::BITS as usize || index < 1usize << path_len
}

/// Verifies a bincode-serialized SP1 6.2.2 `SP1Proof::Compressed` against the certificate.
pub fn verify_sp1_aggchain_proof(
    proof_bytes: &[u8],
    expected_program_vk: &Vkey,
    expected_public_values_hash: &[u8; 32],
) -> Result<(), Sp1AggchainProofError> {
    if expected_program_vk
        .iter()
        .any(|word| *word >= SP1Field::ORDER_U32)
    {
        return Err(Sp1AggchainProofError::ProgramKey);
    }
    let program_vk = expected_program_vk.map(SP1Field::from_canonical_u32);
    let proof: SP1Proof = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(proof_bytes.len() as u64)
        .reject_trailing_bytes()
        .deserialize(proof_bytes)?;
    // Field elements decode from any u32 (`x + p` aliases `x`), so require that the
    // bytes are exactly the canonical re-encoding of what was decoded.
    let canonical = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&proof)?;
    if canonical.as_slice() != proof_bytes {
        return Err(Sp1AggchainProofError::NoncanonicalEncoding);
    }
    let SP1Proof::Compressed(proof) = proof else {
        return Err(Sp1AggchainProofError::ProofType);
    };
    if !merkle_index_is_in_range(
        proof.vk_merkle_proof.index,
        proof.vk_merkle_proof.path.len(),
    ) {
        return Err(Sp1AggchainProofError::MerkleIndex);
    }

    if proof.proof.public_values.len() != RECURSIVE_PROOF_NUM_PV_ELTS {
        return Err(Sp1AggchainProofError::PublicValuesLength);
    }
    let public_values: &RecursionPublicValues<SP1Field> =
        proof.proof.public_values.as_slice().borrow();
    if public_values.exit_code != SP1Field::zero() {
        return Err(Sp1AggchainProofError::ExitCode);
    }
    if !public_values
        .committed_value_digest
        .iter()
        .flatten()
        .zip(expected_public_values_hash)
        .all(|(actual, expected)| actual.as_canonical_u32() == u32::from(*expected))
    {
        return Err(Sp1AggchainProofError::PublicValues);
    }

    SP1CompressedVerifier::new().verify_compressed(&proof, &program_vk)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_encoding() {
        assert!(matches!(
            verify_sp1_aggchain_proof(&[], &[0; 8], &[0; 32]),
            Err(Sp1AggchainProofError::Decode(_))
        ));
    }

    #[test]
    fn rejects_other_proof_types() {
        for proof in [
            SP1Proof::Core(vec![]),
            SP1Proof::Plonk(Default::default()),
            SP1Proof::Groth16(Default::default()),
        ] {
            assert!(matches!(
                verify_sp1_aggchain_proof(&bincode::serialize(&proof).unwrap(), &[0; 8], &[0; 32]),
                Err(Sp1AggchainProofError::ProofType)
            ));
        }
    }

    #[test]
    fn rejects_noncanonical_program_keys() {
        assert!(matches!(
            verify_sp1_aggchain_proof(&[], &[SP1Field::ORDER_U32; 8], &[0; 32]),
            Err(Sp1AggchainProofError::ProgramKey)
        ));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut proof = bincode::serialize(&SP1Proof::Core(vec![])).unwrap();
        proof.push(0);
        assert!(matches!(
            verify_sp1_aggchain_proof(&proof, &[0; 8], &[0; 32]),
            Err(Sp1AggchainProofError::Decode(_))
        ));
    }

    #[test]
    fn rejects_out_of_range_merkle_indices() {
        assert!(merkle_index_is_in_range(0, 0));
        assert!(!merkle_index_is_in_range(1, 0));
        assert!(merkle_index_is_in_range((1 << 18) - 1, 18));
        assert!(!merkle_index_is_in_range(1 << 18, 18));
        assert!(merkle_index_is_in_range(usize::MAX, usize::BITS as usize));
    }
}
