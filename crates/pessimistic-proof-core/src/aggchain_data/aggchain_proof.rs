use agglayer_primitives::Digest;
use serde::{Deserialize, Serialize};
use unified_bridge::AggchainProofPublicValues;

use crate::{
    aggchain_data::Vkey,
    proof::{ConstrainedValues, IMPORTED_BRIDGE_EXIT_COMMITMENT_VERSION},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggchainProof {
    /// Chain-specific commitment forwarded by the PP.
    pub aggchain_params: Digest,
    /// Verifying key for the aggchain proof program.
    pub aggchain_vkey: Vkey,
}

impl AggchainProof {
    /// Verifies the next recursive proof supplied by the active zkVM.
    pub fn verify_aggchain_proof(&self, constrained_values: &ConstrainedValues) {
        let _aggchain_proof_public_values = AggchainProofPublicValues {
            prev_local_exit_root: constrained_values.initial_state_commitment.exit_root.into(),
            new_local_exit_root: constrained_values.final_state_commitment.exit_root.into(),
            l1_info_root: constrained_values.l1_info_root,
            origin_network: constrained_values.origin_network,
            aggchain_params: self.aggchain_params,
            commit_imported_bridge_exits: constrained_values
                .commit_imported_bridge_exits
                .commitment(IMPORTED_BRIDGE_EXIT_COMMITMENT_VERSION),
        };

        #[cfg(all(target_os = "zkvm", feature = "sp1"))]
        {
            // Panic upon invalid proof.
            sp1_zkvm::lib::verify::verify_sp1_proof(
                &self.aggchain_vkey,
                &_aggchain_proof_public_values.hash(),
            );
        }

        #[cfg(all(target_os = "zkvm", feature = "zisk"))]
        {
            let proof = ziskos::io::read_slice();
            assert!(verify_zisk_aggchain_proof(
                proof,
                &self.aggchain_vkey,
                &_aggchain_proof_public_values.hash(),
            ));
        }
    }
}

#[cfg(all(target_os = "zkvm", feature = "zisk"))]
fn verify_zisk_aggchain_proof(
    proof: &[u8],
    expected_program_vk: &Vkey,
    expected_public_values_hash: &[u8; 32],
) -> bool {
    const HEADER_WORDS: usize = 2;
    const PROGRAM_VK_WORDS: usize = 4;
    const USER_PUBLIC_WORDS: usize = 64;
    const PUBLIC_WORDS: usize = PROGRAM_VK_WORDS + USER_PUBLIC_WORDS;
    const TRUSTED_VADCOP_VK: &[u8; 32] =
        include_bytes!(concat!(env!("OUT_DIR"), "/zisk_vadcop_vk.bin"));

    if proof.len() % 8 != 0 {
        return false;
    }

    let word = |index: usize| {
        proof
            .get(index * 8..(index + 1) * 8)
            .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
    };

    let proof_words = proof.len() / 8;
    if word(0) != Some(1)
        || word(1) != Some(PUBLIC_WORDS as u64)
        || proof_words < HEADER_WORDS + PUBLIC_WORDS + TRUSTED_VADCOP_VK.len() / 8
        || proof.get(proof.len() - TRUSTED_VADCOP_VK.len()..)
            != Some(TRUSTED_VADCOP_VK.as_slice())
    {
        return false;
    }

    let mut actual_program_vk = [0u32; 8];
    for limb_index in 0..PROGRAM_VK_WORDS {
        let Some(limb) = word(HEADER_WORDS + limb_index) else {
            return false;
        };
        let bytes = limb.to_be_bytes();
        actual_program_vk[limb_index * 2] = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        actual_program_vk[limb_index * 2 + 1] =
            u32::from_be_bytes(bytes[4..].try_into().unwrap());
    }
    if &actual_program_vk != expected_program_vk {
        return false;
    }

    let public_values_offset = HEADER_WORDS + PROGRAM_VK_WORDS;
    let mut actual_public_values_hash = [0u8; 32];
    for index in 0..8 {
        let Some(value) = word(public_values_offset + index) else {
            return false;
        };
        actual_public_values_hash[index * 4..(index + 1) * 4]
            .copy_from_slice(&(value as u32).to_le_bytes());
    }
    if &actual_public_values_hash != expected_public_values_hash {
        return false;
    }

    unsafe { ziskos::zisklib::verify_zisk_proof_c(proof.as_ptr(), proof.len()) }
}
