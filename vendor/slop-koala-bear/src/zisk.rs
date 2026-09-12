//! ZisK backend for the width-16 permutation: converts Montgomery lanes to canonical
//! words, calls the precompile, and converts back. Selected by the `zisk-precompile` feature.

use serde::{Deserialize, Serialize};
use slop_algebra::{AbstractField, PrimeField32};
use slop_symmetric::{CryptographicPermutation, Permutation};

use crate::KoalaBear;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct ZiskKoalaPerm;

impl Permutation<[KoalaBear; 16]> for ZiskKoalaPerm {
    fn permute_mut(&self, state: &mut [KoalaBear; 16]) {
        let canonical = state.map(|lane| lane.as_canonical_u32());
        let mut words = core::array::from_fn(|i| {
            u64::from(canonical[2 * i]) | (u64::from(canonical[2 * i + 1]) << 32)
        });
        unsafe { ziskos::syscalls::syscall_koala_poseidon2(&mut words) };
        for (i, lane) in state.iter_mut().enumerate() {
            let value = (words[i / 2] >> (32 * (i % 2))) as u32;
            assert!(
                value < KoalaBear::ORDER_U32,
                "noncanonical KoalaBear precompile output"
            );
            *lane = KoalaBear::from_canonical_u32(value);
        }
    }
}

impl CryptographicPermutation<[KoalaBear; 16]> for ZiskKoalaPerm {}
