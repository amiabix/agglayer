#![no_main]

use agglayer_primitives::{keccak::keccak256_combine, B256};
use ecdsa_proof_lib::AggchainECDSA;

ziskos::entrypoint!(main);

pub fn main() {
    let aggchain_ecdsa = ziskos::io::read::<AggchainECDSA>();
    let combined_hash = keccak256_combine([
        aggchain_ecdsa.new_local_exit_root.as_ref(),
        aggchain_ecdsa.commit_imported_bridge_exits.as_ref(),
    ]);
    let recovered_signer = aggchain_ecdsa
        .signature
        .recover_address_from_prehash(&B256::new(combined_hash.0))
        .expect("invalid signature");
    assert_eq!(recovered_signer, aggchain_ecdsa.signer);

    ziskos::io::commit_slice(&aggchain_ecdsa.public_values().hash());
}
