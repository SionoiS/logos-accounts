//! Transient open helper: VLAD + `/entrykey` ephemerals, external public `/pubkey`.
//!
//! Used only for the duration of [`crate::api::create_account`]. Does not store
//! long-lived secrets. Root private keys never enter this type.

use crate::config::pubkey_key_path;
use crate::Error;
use bs_traits::asyncro::{AsyncKeyManager, AsyncMultiSigner, AsyncSigner, BoxFuture, SignerFuture};
use bs_traits::{EphemeralKey, GetKey, Signer, Verifier};
use multicodec::Codec;
use multikey::{Multikey, Views};
use multisig::Multisig;
use provenance_log::Key;
use std::num::NonZeroUsize;

type EphemeralSigningTuple<E> =
    Result<(Multikey, Box<dyn FnOnce(&[u8]) -> Result<Multisig, E> + Send>), E>;

/// One-shot BetterSign open: software ephemerals + injected root Multikey (public).
#[derive(Clone, Debug)]
pub struct EphemeralOpenHelper {
    root_pubkey: Multikey,
}

impl EphemeralOpenHelper {
    /// Build a helper that returns `root_pubkey` for `/pubkey` KeyGen resolution.
    ///
    /// `root_pubkey` must be a Multikey usable as a public verification key
    /// (secret keys are converted to public via Multikey views when possible).
    pub fn new(root_pubkey: Multikey) -> Result<Self, Error> {
        let root_pubkey = ensure_public_multikey(root_pubkey)?;
        Ok(Self { root_pubkey })
    }

    fn prepare_ephemeral_inner(
        &self,
        codec: &Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> EphemeralSigningTuple<Error> {
        require_secp256k1_priv(codec)?;

        let mut rng = rand_core::OsRng;
        let secret_key = multikey::Builder::new_from_random_bytes(*codec, &mut rng)?
            .with_threshold(threshold)
            .with_limit(limit)
            .try_build()?;

        let public_key = secret_key.conv_view()?.to_public_key()?;

        let sign_once = Box::new(move |data: &[u8]| -> Result<Multisig, Error> {
            let signature = secret_key.sign_view()?.sign(data, false, None)?;
            Ok(signature)
        });

        Ok((public_key, sign_once))
    }

    fn get_root_or_err(&self, key_path: &Key) -> Result<Multikey, Error> {
        if key_path == &pubkey_key_path() {
            return Ok(self.root_pubkey.clone());
        }
        Err(Error::InvalidOp(format!(
            "ephemeral open helper has no long-lived key for {key_path} (only /pubkey is injected)"
        )))
    }
}

fn ensure_public_multikey(mk: Multikey) -> Result<Multikey, Error> {
    if mk.attr_view()?.is_secret_key() {
        Ok(mk.conv_view()?.to_public_key()?)
    } else {
        Ok(mk)
    }
}

fn require_secp256k1_priv(codec: &Codec) -> Result<(), Error> {
    match codec {
        Codec::Secp256K1Priv => Ok(()),
        other => Err(Error::UnsupportedCodec(*other)),
    }
}

impl GetKey for EphemeralOpenHelper {
    type KeyPath = Key;
    type Codec = Codec;
    type Key = Multikey;
    type Error = Error;
}

impl Signer for EphemeralOpenHelper {
    type KeyPath = Key;
    type Signature = Multisig;
    type Error = Error;
}

impl EphemeralKey for EphemeralOpenHelper {
    type PubKey = Multikey;
}

impl Verifier for EphemeralOpenHelper {
    type Key = Multikey;
    type Signature = Multisig;
    type Error = Error;
}

impl AsyncSigner for EphemeralOpenHelper {
    fn try_sign<'a>(
        &'a self,
        key_path: &'a Self::KeyPath,
        _data: &'a [u8],
    ) -> SignerFuture<'a, Self::Signature, Self::Error> {
        Box::pin(async move {
            Err(Error::InvalidOp(format!(
                "ephemeral open helper cannot try_sign({key_path}); long-lived keys are external"
            )))
        })
    }
}

impl AsyncKeyManager<Error> for EphemeralOpenHelper {
    fn get_key<'a>(
        &'a self,
        key_path: &'a Self::KeyPath,
        codec: &'a Self::Codec,
        _threshold: NonZeroUsize,
        _limit: NonZeroUsize,
    ) -> BoxFuture<'a, Result<Self::Key, Error>> {
        Box::pin(async move {
            // Open only KeyGens /pubkey via this helper; codec is advisory for secp defaults.
            let _ = codec;
            self.get_root_or_err(key_path)
        })
    }

    fn preprocess_vlad<'a>(
        &'a mut self,
        _vlad: &'a multicid::Vlad,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move { Ok(()) })
    }
}

impl AsyncMultiSigner<Multisig, Error> for EphemeralOpenHelper {
    fn prepare_ephemeral_signing<'a>(
        &'a self,
        codec: &'a Self::Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> BoxFuture<'a, EphemeralSigningTuple<Error>> {
        Box::pin(async move { self.prepare_ephemeral_inner(codec, threshold, limit) })
    }
}

/// Open a new provenance log with peer-provided root Multikey (public) and software ephemerals.
pub async fn open_plog_with_external_pubkey(root_pubkey: Multikey) -> Result<provenance_log::Log, Error> {
    use bs::config::asynchronous::{KeyManager, MultiSigner};
    use bs::ops::open;

    let helper = EphemeralOpenHelper::new(root_pubkey)?;
    // Same pattern as BetterSign::new: KM and signer are clones of one helper.
    let mut km = helper.clone();
    let signer = helper;
    // Trait object coherence: ensure supertraits are satisfied at compile time.
    fn _assert_km<T: KeyManager<Error>>(_: &T) {}
    fn _assert_ms<T: MultiSigner<Error>>(_: &T) {}
    _assert_km(&km);
    _assert_ms(&signer);

    let config = crate::config::default_open_config();
    let log = open::open_plog(&config, &mut km, &signer).await?;
    Ok(log)
}

#[cfg(test)]
mod tests {
    use super::*;
    use multikey::Builder;

    fn test_root_pubkey() -> Multikey {
        let mut rng = rand_core::OsRng;
        let sk = Builder::new_from_random_bytes(Codec::Secp256K1Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        sk.conv_view().unwrap().to_public_key().unwrap()
    }

    #[tokio::test]
    async fn open_produces_verified_log_with_pubkey() {
        let pk = test_root_pubkey();
        let log = open_plog_with_external_pubkey(pk.clone())
            .await
            .expect("open");
        crate::api::ensure_plog_verified(&log).expect("verify");
        let v = crate::api::get_plog_value(&log, "/pubkey").expect("pubkey path");
        match v {
            crate::api::PlogPathValue::Bin(s) => {
                let decoded = crate::encoding::decode_multikey(&s).unwrap();
                // Same public key material as injected.
                assert_eq!(
                    decoded.data_view().unwrap().key_bytes().unwrap(),
                    pk.data_view().unwrap().key_bytes().unwrap()
                );
            }
            other => panic!("expected bin pubkey, got {other:?}"),
        }
    }
}
