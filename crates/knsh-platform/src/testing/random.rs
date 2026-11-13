//! A reproducible random stream.

use std::sync::Mutex;

use super::lock;
use crate::error::PlatformError;
use crate::random::Random;

/// `SplitMix64` from a seed: the same seed always yields the same bytes. Not cryptographic.
#[derive(Debug)]
pub struct SeededRandom {
    state: Mutex<u64>,
}

impl SeededRandom {
    /// A stream starting from `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            state: Mutex::new(seed),
        }
    }
}

/// One `SplitMix64` step (Steele, Lea and Flood, 2014).
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl Random for SeededRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), PlatformError> {
        let mut state = lock(&self.state);
        for chunk in buf.chunks_mut(8) {
            let bytes = splitmix64(&mut state).to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream_different_seed_different_stream() {
        let first = SeededRandom::new(7);
        let same = SeededRandom::new(7);
        let other = SeededRandom::new(8);
        let mut bytes = [[0u8; 13]; 3];
        first.fill(&mut bytes[0]).unwrap();
        same.fill(&mut bytes[1]).unwrap();
        other.fill(&mut bytes[2]).unwrap();
        assert_eq!(bytes[0], bytes[1]);
        assert_ne!(bytes[0], bytes[2]);
        assert_eq!(first.next_u64(), same.next_u64());
        // Known first output of SplitMix64 for seed 0.
        assert_eq!(SeededRandom::new(0).next_u64(), Ok(0xE220_A839_7B1D_CDAF));
    }
}
