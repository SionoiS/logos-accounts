//! Multikey / Multisig helpers (no hardware or long-lived wallet bridges).

use crate::Error;
use multicodec::Codec;
use multikey::{Builder as MkBuilder, Multikey, Views};
use multisig::{ms, Multisig};
use sha2::{Digest, Sha256};

/// SHA-256 digest length.
pub const PREHASH_LEN: usize = 32;

/// Compute SHA-256(data).
pub fn sha256_prehash(data: &[u8]) -> [u8; PREHASH_LEN] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; PREHASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Build a Multikey public key from raw compressed SEC1 bytes (33 bytes).
pub fn sec1_to_multikey(sec1: &[u8]) -> Result<Multikey, Error> {
    if sec1.len() != 33 {
        return Err(Error::Message(format!(
            "expected 33-byte compressed SEC1 public key, got {} bytes",
            sec1.len()
        )));
    }
    let owned = sec1.to_vec();
    Ok(MkBuilder::new(Codec::Secp256K1Pub)
        .with_key_bytes(&owned)
        .try_build()?)
}

/// Extract compressed SEC1 bytes from a Multikey secp256k1 public (or secret) key.
pub fn multikey_to_sec1(mk: &Multikey) -> Result<Vec<u8>, Error> {
    let pub_mk = if mk.attr_view()?.is_secret_key() {
        mk.conv_view()?.to_public_key()?
    } else {
        mk.clone()
    };
    let bytes = pub_mk.data_view()?.key_bytes()?;
    Ok(bytes.to_vec())
}

/// Convert a raw ECDSA signature (r‖s, 64 bytes) into a Multisig (`Es256KMsig`).
pub fn signature_bytes_to_multisig(sig_rs: &[u8]) -> Result<Multisig, Error> {
    if sig_rs.len() != 64 {
        return Err(Error::Message(format!(
            "expected 64-byte ECDSA signature (r||s), got {} bytes",
            sig_rs.len()
        )));
    }
    let owned = sig_rs.to_vec();
    Ok(ms::Builder::new(Codec::Es256KMsig)
        .with_signature_bytes(&owned)
        .try_build()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use multikey::Builder;
    use rand_core::OsRng;

    #[test]
    fn sha256_prehash_is_32_bytes() {
        let h = sha256_prehash(b"hello");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn multikey_sec1_roundtrip() {
        let mut rng = OsRng;
        let sk = Builder::new_from_random_bytes(Codec::Secp256K1Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();
        let sec1 = multikey_to_sec1(&pk).unwrap();
        assert_eq!(sec1.len(), 33);
        let mk2 = sec1_to_multikey(&sec1).unwrap();
        assert_eq!(multikey_to_sec1(&mk2).unwrap(), sec1);
    }
}
