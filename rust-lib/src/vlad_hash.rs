//! Cache key hashing for multibase VLADs (`SHA-256` of canonical multibase).

use crate::encoding::encode_vlad;
use multicid::Vlad;
use sha2::{Digest, Sha256};

/// Length of a VLAD cache key / prehash (32 bytes).
pub const VLAD_HASH_LEN: usize = 32;

/// Compute the 32-byte hash for a multibase VLAD string.
pub fn vlad_hash_from_multibase(vlad_multibase: &str) -> [u8; VLAD_HASH_LEN] {
    let digest = Sha256::digest(vlad_multibase.as_bytes());
    let mut out = [0u8; VLAD_HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Compute the 32-byte hash for a [`Vlad`] (canonical multibase encoding).
pub fn vlad_hash(vlad: &Vlad) -> [u8; VLAD_HASH_LEN] {
    vlad_hash_from_multibase(&encode_vlad(vlad))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_32_bytes_and_stable() {
        let s = "zSampleVladMultibaseNotReal";
        let h1 = vlad_hash_from_multibase(s);
        let h2 = vlad_hash_from_multibase(s);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
        assert_ne!(h1, vlad_hash_from_multibase("other"));
    }
}
