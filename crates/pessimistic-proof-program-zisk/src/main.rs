#![no_main]

use pessimistic_proof_core::{
    generate_pessimistic_proof, multi_batch_header::MultiBatchHeader, NetworkState,
    PessimisticProofOutput,
};

ziskos::entrypoint!(main);

pub fn main() {
    let initial_state = ziskos::io::read::<NetworkState>();
    let batch_header = ziskos::io::read::<MultiBatchHeader>();

    let (output, _final_state) = generate_pessimistic_proof(initial_state, &batch_header).unwrap();

    let public_values = PessimisticProofOutput::bincode_codec()
        .serialize(&output)
        .unwrap();

    ziskos::io::commit_slice(&public_values);
}
