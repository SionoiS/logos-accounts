//! Bridges between Keycard (k256 / alloy signatures) and Multikey / Multisig.

use crate::Error;
use k256::PublicKey;
use multicodec::Codec;
use multikey::{Builder as MkBuilder, Multikey, Views};
use multisig::{ms, Multisig};
use sha2::{Digest, Sha256};

/// SHA-256 digest length required by Keycard `sign`.
pub const PREHASH_LEN: usize = 32;

/// Compute SHA-256(data) — the prehash Multikey secp256k1 software signing
/// applies internally via k256 `Signer::try_sign`, and that Keycard must receive.
pub fn sha256_prehash(data: &[u8]) -> [u8; PREHASH_LEN] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; PREHASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// Build a Multikey public key (`Codec::Secp256K1Pub`) from a k256 `PublicKey`.
///
/// Uses compressed SEC1 encoding (33 bytes), matching Multikey's secp256k1 view.
pub fn public_key_to_multikey(public_key: &PublicKey) -> Result<Multikey, Error> {
    let sec1 = public_key.to_sec1_bytes();
    Ok(MkBuilder::new(Codec::Secp256K1Pub)
        .with_key_bytes(&sec1)
        .try_build()?)
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

/// Convert an alloy / Keycard signature into Multisig.
///
/// Takes the first 64 bytes (r‖s) of the 65-byte Electrum form; recovery id is
/// not stored in Multisig Es256K.
pub fn alloy_signature_to_multisig(sig: &alloy_primitives::Signature) -> Result<Multisig, Error> {
    let bytes = sig.as_bytes();
    let rs: [u8; 64] = bytes[..64]
        .try_into()
        .map_err(|_| Error::Message("signature truncated".into()))?;
    Ok(ms::Builder::new(Codec::Es256KMsig)
        .with_signature_bytes(&rs)
        .try_build()?)
}

/// Fingerprint a Multikey with SHA2-256 (same convention as `InMemoryKeyManager`).
pub fn fingerprint_sha256(mk: &Multikey) -> Result<Vec<u8>, Error> {
    let fp = mk.fingerprint_view()?.fingerprint(Codec::Sha2256)?;
    Ok(fp.into())
}

/// Ensure the codec is secp256k1 private (keygen / ephemeral params).
pub fn require_secp256k1_priv(codec: &Codec) -> Result<(), Error> {
    match codec {
        Codec::Secp256K1Priv => Ok(()),
        other => Err(Error::UnsupportedCodec(*other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand_core::OsRng;

    #[test]
    fn sha256_prehash_is_32_bytes() {
        let h = sha256_prehash(b"hello");
        assert_eq!(h.len(), 32);
        // known SHA-256("hello")
        let expected = hex_literal_sha256_hello();
        assert_eq!(h, expected);
    }

    fn hex_literal_sha256_hello() -> [u8; 32] {
        // echo -n hello | sha256sum
        [
            0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e, 0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9,
            0xe2, 0x9e, 0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e, 0x73, 0x04, 0x33, 0x62,
            0x93, 0x8b, 0x98, 0x24,
        ]
    }

    #[test]
    fn sec1_roundtrip_via_multikey() {
        let sk = SigningKey::random(&mut OsRng);
        let vk = sk.verifying_key();
        let pk = PublicKey::from(vk);
        let mk = public_key_to_multikey(&pk).unwrap();
        assert!(mk.attr_view().unwrap().is_public_key());
        let sec1 = multikey_to_sec1(&mk).unwrap();
        assert_eq!(sec1.as_slice(), pk.to_sec1_bytes().as_ref());
        let mk2 = sec1_to_multikey(&sec1).unwrap();
        assert_eq!(multikey_to_sec1(&mk2).unwrap(), sec1);
    }

    #[test]
    fn signature_to_multisig_and_verify() {
        let sk = SigningKey::random(&mut OsRng);
        let msg = b"test message for multisig";
        // k256 Signer::try_sign hashes with SHA-256 (DigestSigner path)
        let sig: Signature = sk.sign(msg);
        let multisig = signature_bytes_to_multisig(&sig.to_bytes()).unwrap();

        let pk = PublicKey::from(sk.verifying_key());
        let mk = public_key_to_multikey(&pk).unwrap();
        mk.verify_view()
            .unwrap()
            .verify(&multisig, Some(msg))
            .expect("Multikey verify should accept matching Es256K signature");
    }

    #[test]
    fn require_secp_rejects_ed25519() {
        let err = require_secp256k1_priv(&Codec::Ed25519Priv).unwrap_err();
        assert!(matches!(err, Error::UnsupportedCodec(Codec::Ed25519Priv)));
    }
}
