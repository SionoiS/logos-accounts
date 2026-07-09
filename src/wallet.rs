//! Keycard-backed wallet implementing BetterSign `KeyManager` + `MultiSigner`.
//!
//! # Hybrid crypto model
//!
//! | Key role | Storage | Mechanism |
//! |----------|---------|-----------|
//! | VLAD / first-entry ephemeral | Software one-shot | `prepare_ephemeral_signing` |
//! | Long-lived `/pubkey` | Keycard BIP32 path | `get_key` / `try_sign` |
//!
//! Ephemeral secrets must be destroyable after VLAD / first-entry binding; Keycard
//! cannot model that, so those keys never leave process memory.

use crate::convert::{
    alloy_signature_to_multisig, fingerprint_sha256, public_key_to_multikey, require_secp256k1_priv,
    sha256_prehash,
};
use crate::error::{lock_err, Error};
use crate::keycard_session::{KeycardSession, SharedKeycard};
use crate::path_map::{parse_derivation_path, PathMap, DEFAULT_PUBKEY_PATH};
use crate::verifier::MultikeyVerifier;
use bip32::DerivationPath;
use bs_traits::asyncro::{AsyncKeyManager, AsyncMultiSigner, AsyncSigner, BoxFuture, SignerFuture};
use bs_traits::sync::{
    EphemeralSigningTuple, SyncGetKey, SyncPrepareEphemeralSigning, SyncSigner, SyncVerifier,
};
use bs_traits::{EphemeralKey, GetKey, Signer, Verifier};
use multicodec::Codec;
use multikey::{Multikey, Views};
use multisig::Multisig;
use nexum_apdu_core::prelude::CardTransport;
use provenance_log::Key;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

/// Default logical path for the advertised long-lived public key.
pub fn default_pubkey_key() -> Key {
    Key::try_from("/pubkey").expect("/pubkey is a valid provenance_log::Key")
}

/// Keycard-backed wallet: key manager + multi-signer for BetterSign.
///
/// Associated types match `bs::config` opinionated supertraits:
/// - `KeyPath` = `provenance_log::Key`
/// - `Codec` = `multicodec::Codec`
/// - `Key` / `PubKey` = `multikey::Multikey`
/// - `Signature` = `multisig::Multisig`
/// - `Error` = project [`Error`] (or a compatible `E`)
pub struct KeycardWallet<T: CardTransport, E = Error> {
    session: KeycardSession<T>,
    path_map: Arc<PathMap>,
    /// Logical key path → Multikey public key cache (never private material from card).
    pub_cache: Arc<Mutex<HashMap<Key, Multikey>>>,
    /// Optional fingerprint index (path → fingerprint bytes), for parity with in-memory wallet.
    fingerprints: Arc<Mutex<HashMap<Key, Vec<u8>>>>,
    _phantom: PhantomData<E>,
}

impl<T: CardTransport, E> Clone for KeycardWallet<T, E> {
    fn clone(&self) -> Self {
        Self {
            session: self.session.clone(),
            path_map: Arc::clone(&self.path_map),
            pub_cache: Arc::clone(&self.pub_cache),
            fingerprints: Arc::clone(&self.fingerprints),
            _phantom: PhantomData,
        }
    }
}

impl<T: CardTransport, E> std::fmt::Debug for KeycardWallet<T, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeycardWallet")
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

impl<T, E> KeycardWallet<T, E>
where
    T: CardTransport + 'static,
    E: From<Error> + From<multikey::Error> + From<multihash::Error> + std::fmt::Debug,
{
    /// Build a wallet around an existing session, mapping `/pubkey` to `pubkey_derivation`
    /// (default [`DEFAULT_PUBKEY_PATH`]).
    pub fn new(session: KeycardSession<T>, pubkey_derivation: Option<&str>) -> Result<Self, E> {
        let path_map = PathMap::with_default_pubkey(pubkey_derivation).map_err(E::from)?;
        Ok(Self {
            session,
            path_map: Arc::new(path_map),
            pub_cache: Arc::new(Mutex::new(HashMap::new())),
            fingerprints: Arc::new(Mutex::new(HashMap::new())),
            _phantom: PhantomData,
        })
    }

    /// Connect with known credentials and default `/pubkey` derivation.
    pub fn with_known_credentials(
        transport: T,
        pin: impl Into<String>,
        pairing_key: [u8; 32],
        pairing_index: u8,
        pubkey_derivation: Option<&str>,
    ) -> Result<Self, E> {
        let session = KeycardSession::with_known_credentials(
            transport,
            pin,
            pairing_key,
            pairing_index,
        )
        .map_err(E::from)?;
        Self::new(session, pubkey_derivation)
    }

    /// Wrap a pre-built shared Keycard handle.
    pub fn from_shared_card(
        card: SharedKeycard<T>,
        pubkey_derivation: Option<&str>,
    ) -> Result<Self, E> {
        Self::new(KeycardSession::from_shared(card), pubkey_derivation)
    }

    /// Register an additional logical key → BIP32 path (e.g. rotation).
    pub fn register_path(&self, key: Key, derivation: &str) -> Result<(), E> {
        let path = parse_derivation_path(derivation).map_err(E::from)?;
        self.path_map.register(key, path).map_err(E::from)
    }

    /// Register with a parsed BIP32 path.
    pub fn register_derivation(&self, key: Key, path: DerivationPath) -> Result<(), E> {
        self.path_map.register(key, path).map_err(E::from)
    }

    /// Access the underlying session.
    pub fn session(&self) -> &KeycardSession<T> {
        &self.session
    }

    /// Path map (logical → BIP32).
    pub fn path_map(&self) -> &PathMap {
        &self.path_map
    }

    /// Cached public Multikey for a path, if any.
    pub fn cached_public_key(&self, key: &Key) -> Result<Option<Multikey>, E> {
        let guard = self.pub_cache.lock().map_err(lock_err).map_err(E::from)?;
        Ok(guard.get(key).cloned())
    }

    /// Drop a cached public key (e.g. before rotation so the next `get_key` re-exports).
    pub fn clear_cached_public_key(&self, key: &Key) -> Result<(), E> {
        {
            let mut cache = self.pub_cache.lock().map_err(lock_err).map_err(E::from)?;
            cache.remove(key);
        }
        let mut fps = self.fingerprints.lock().map_err(lock_err).map_err(E::from)?;
        fps.remove(key);
        Ok(())
    }

    /// Replace the BIP32 mapping for `key` and clear any cached Multikey.
    pub fn rebind_path(&self, key: Key, derivation: &str) -> Result<(), E> {
        self.clear_cached_public_key(&key)?;
        self.register_path(key, derivation)
    }

    /// Software Multikey verifier helper bound to the same error type.
    pub fn verifier(&self) -> MultikeyVerifier<E>
    where
        E: From<Error>,
    {
        MultikeyVerifier::new()
    }

    fn cache_public(&self, key: &Key, mk: Multikey) -> Result<(), E> {
        let fp = fingerprint_sha256(&mk).map_err(E::from)?;
        {
            let mut fps = self.fingerprints.lock().map_err(lock_err).map_err(E::from)?;
            fps.insert(key.clone(), fp);
        }
        let mut cache = self.pub_cache.lock().map_err(lock_err).map_err(E::from)?;
        cache.insert(key.clone(), mk);
        Ok(())
    }

    fn get_cached(&self, key: &Key) -> Result<Option<Multikey>, E> {
        let guard = self.pub_cache.lock().map_err(lock_err).map_err(E::from)?;
        Ok(guard.get(key).cloned())
    }

    /// Export public key from card for a registered path and cache it.
    fn export_and_cache(&self, key_path: &Key) -> Result<Multikey, E> {
        let derivation = self.path_map.require(key_path).map_err(E::from)?;
        let pk = self
            .session
            .export_public_key_blocking(&derivation)
            .map_err(E::from)?;
        let mk = public_key_to_multikey(&pk).map_err(E::from)?;
        self.cache_public(key_path, mk.clone())?;
        tracing::debug!(%key_path, path = %derivation, "exported public key from Keycard");
        Ok(mk)
    }

    async fn export_and_cache_async(&self, key_path: &Key) -> Result<Multikey, E> {
        let derivation = self.path_map.require(key_path).map_err(E::from)?;
        let pk = self
            .session
            .export_public_key(&derivation)
            .await
            .map_err(E::from)?;
        let mk = public_key_to_multikey(&pk).map_err(E::from)?;
        self.cache_public(key_path, mk.clone())?;
        tracing::debug!(%key_path, path = %derivation, "exported public key from Keycard (async)");
        Ok(mk)
    }

    fn sign_with_card(&self, key_path: &Key, data: &[u8]) -> Result<Multisig, E> {
        let derivation = self.path_map.require(key_path).map_err(E::from)?;
        let digest = sha256_prehash(data);
        let sig = self
            .session
            .sign_prehash_blocking(&digest, &derivation)
            .map_err(E::from)?;
        let multisig = alloy_signature_to_multisig(&sig).map_err(E::from)?;

        // Optional self-check when we already have the public key cached
        if let Some(pk) = self.get_cached(key_path)?
            && let Err(e) = pk.verify_view()?.verify(&multisig, Some(data))
        {
            tracing::warn!(%key_path, error = %e, "card signature failed local Multikey verify");
            return Err(E::from(Error::from(e)));
        }

        Ok(multisig)
    }

    async fn sign_with_card_async(&self, key_path: &Key, data: &[u8]) -> Result<Multisig, E> {
        let derivation = self.path_map.require(key_path).map_err(E::from)?;
        let digest = sha256_prehash(data);
        let sig = self
            .session
            .sign_prehash(&digest, &derivation)
            .await
            .map_err(E::from)?;
        let multisig = alloy_signature_to_multisig(&sig).map_err(E::from)?;

        if let Some(pk) = self.get_cached(key_path)?
            && let Err(e) = pk.verify_view()?.verify(&multisig, Some(data))
        {
            tracing::warn!(%key_path, error = %e, "card signature failed local Multikey verify");
            return Err(E::from(Error::from(e)));
        }

        Ok(multisig)
    }

    fn prepare_ephemeral_inner(
        &self,
        codec: &Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> EphemeralSigningTuple<Multikey, Multisig, E> {
        require_secp256k1_priv(codec).map_err(E::from)?;

        let mut rng = rand_core::OsRng;
        let secret_key = multikey::Builder::new_from_random_bytes(*codec, &mut rng)
            .map_err(E::from)?
            .with_threshold(threshold)
            .with_limit(limit)
            .try_build()
            .map_err(E::from)?;

        let public_key = secret_key.conv_view().map_err(E::from)?.to_public_key().map_err(E::from)?;

        let sign_once = Box::new(move |data: &[u8]| -> Result<Multisig, E> {
            let signature = secret_key
                .sign_view()
                .map_err(E::from)?
                .sign(data, false, None)
                .map_err(E::from)?;
            Ok(signature)
        });

        Ok((public_key, sign_once))
    }
}

// --- Marker traits (associated types) ---

impl<T, E> GetKey for KeycardWallet<T, E>
where
    T: CardTransport,
    E: std::fmt::Debug,
{
    type KeyPath = Key;
    type Codec = Codec;
    type Key = Multikey;
    type Error = E;
}

impl<T, E> Signer for KeycardWallet<T, E>
where
    T: CardTransport,
    E: std::fmt::Debug,
{
    type KeyPath = Key;
    type Signature = Multisig;
    type Error = E;
}

impl<T, E> EphemeralKey for KeycardWallet<T, E>
where
    T: CardTransport,
{
    type PubKey = Multikey;
}

impl<T, E> Verifier for KeycardWallet<T, E>
where
    T: CardTransport,
    E: std::fmt::Debug,
{
    type Key = Multikey;
    type Signature = Multisig;
    type Error = E;
}

// --- Sync traits ---

impl<T, E> SyncGetKey for KeycardWallet<T, E>
where
    T: CardTransport + 'static,
    E: From<Error>
        + From<multikey::Error>
        + From<multihash::Error>
        + std::fmt::Debug,
{
    fn get_key(
        &self,
        key_path: &Self::KeyPath,
        codec: &Self::Codec,
        _threshold: NonZeroUsize,
        _limit: NonZeroUsize,
    ) -> Result<Self::Key, Self::Error> {
        tracing::trace!(%key_path, ?codec, "KeycardWallet::get_key");
        require_secp256k1_priv(codec).map_err(E::from)?;

        if let Some(mk) = self.get_cached(key_path)? {
            return Ok(mk);
        }

        // Unmapped paths are rejected (explicit registration policy).
        self.export_and_cache(key_path)
    }
}

impl<T, E> SyncSigner for KeycardWallet<T, E>
where
    T: CardTransport + 'static,
    E: From<Error>
        + From<multikey::Error>
        + From<multihash::Error>
        + From<multicid::Error>
        + std::fmt::Debug,
{
    fn try_sign(
        &self,
        key_path: &Self::KeyPath,
        data: &[u8],
    ) -> Result<Self::Signature, Self::Error> {
        tracing::trace!(%key_path, len = data.len(), "KeycardWallet::try_sign");
        self.sign_with_card(key_path, data)
    }
}

impl<T, E> SyncPrepareEphemeralSigning for KeycardWallet<T, E>
where
    T: CardTransport + 'static,
    E: From<Error>
        + From<multikey::Error>
        + From<multihash::Error>
        + From<multicid::Error>
        + std::fmt::Debug
        + 'static,
{
    type Codec = Codec;

    fn prepare_ephemeral_signing(
        &self,
        codec: &Self::Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> EphemeralSigningTuple<
        <Self as EphemeralKey>::PubKey,
        <Self as Signer>::Signature,
        <Self as Signer>::Error,
    > {
        tracing::trace!(?codec, "KeycardWallet::prepare_ephemeral_signing (software)");
        self.prepare_ephemeral_inner(codec, threshold, limit)
    }
}

impl<T, E> SyncVerifier for KeycardWallet<T, E>
where
    T: CardTransport + 'static,
    E: From<Error> + From<multikey::Error> + std::fmt::Debug,
{
    fn verify(
        &self,
        key: &Self::Key,
        data: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), Self::Error> {
        key.verify_view()?.verify(signature, Some(data))?;
        Ok(())
    }
}

// --- Async traits ---

impl<T, E> AsyncSigner for KeycardWallet<T, E>
where
    T: CardTransport + 'static,
    E: From<Error>
        + From<multikey::Error>
        + From<multihash::Error>
        + From<multicid::Error>
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
{
    fn try_sign<'a>(
        &'a self,
        key_path: &'a Self::KeyPath,
        data: &'a [u8],
    ) -> SignerFuture<'a, Self::Signature, Self::Error> {
        Box::pin(async move { self.sign_with_card_async(key_path, data).await })
    }
}

impl<T, E> AsyncKeyManager<E> for KeycardWallet<T, E>
where
    T: CardTransport + 'static,
    E: From<Error>
        + From<multikey::Error>
        + From<multihash::Error>
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
{
    fn get_key<'a>(
        &'a self,
        key_path: &'a Self::KeyPath,
        codec: &'a Self::Codec,
        _threshold: NonZeroUsize,
        _limit: NonZeroUsize,
    ) -> BoxFuture<'a, Result<Self::Key, E>> {
        Box::pin(async move {
            tracing::trace!(%key_path, ?codec, "KeycardWallet::get_key (async)");
            require_secp256k1_priv(codec).map_err(E::from)?;
            if let Some(mk) = self.get_cached(key_path)? {
                return Ok(mk);
            }
            self.export_and_cache_async(key_path).await
        })
    }

    fn preprocess_vlad<'a>(
        &'a mut self,
        _vlad: &'a multicid::Vlad,
    ) -> BoxFuture<'a, Result<(), E>> {
        // No-op: VLAD persistence is a Phase 2 concern.
        Box::pin(async move { Ok(()) })
    }
}

impl<T, E> AsyncMultiSigner<Multisig, E> for KeycardWallet<T, E>
where
    T: CardTransport + 'static,
    E: From<Error>
        + From<multikey::Error>
        + From<multihash::Error>
        + From<multicid::Error>
        + std::fmt::Debug
        + Send
        + Sync
        + 'static,
{
    fn prepare_ephemeral_signing<'a>(
        &'a self,
        codec: &'a <Self as GetKey>::Codec,
        threshold: NonZeroUsize,
        limit: NonZeroUsize,
    ) -> BoxFuture<'a, EphemeralSigningTuple<Self::PubKey, Multisig, E>> {
        Box::pin(async move { self.prepare_ephemeral_inner(codec, threshold, limit) })
    }
}

/// Compile-time assertion that `W` satisfies async BetterSign supertraits.
pub fn assert_async_wallet<W, E>()
where
    E: bs::error::BsCompatibleError + Send + 'static,
    W: bs::config::asynchronous::KeyManager<E> + bs::config::asynchronous::MultiSigner<E>,
{
}

/// Compile-time assertion that `W` satisfies sync BetterSign supertraits.
pub fn assert_sync_wallet<W, E>()
where
    E: std::fmt::Debug,
    W: bs::config::sync::KeyManager<E> + bs::config::sync::MultiSigner<E>,
{
}

/// Default derivation string used when none is supplied.
pub fn default_pubkey_derivation() -> &'static str {
    DEFAULT_PUBKEY_PATH
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::verify_multikey;
    use std::num::NonZero;

    /// Dummy transport so we can name `KeycardWallet<DummyTransport>` in type-level tests.
    /// Never used at runtime in these unit tests (ephemeral path ignores the card).
    #[derive(Debug)]
    struct DummyTransport;

    impl CardTransport for DummyTransport {
        fn transmit_raw(
            &mut self,
            _command: &[u8],
        ) -> Result<bytes::Bytes, nexum_apdu_core::Error> {
            Err(nexum_apdu_core::Error::message(
                "DummyTransport: no card in unit tests".to_string(),
            ))
        }

        fn reset(&mut self) -> Result<(), nexum_apdu_core::Error> {
            Ok(())
        }
    }

    #[test]
    fn assert_trait_bounds_compile() {
        // Type-level only — never constructs a wallet.
        fn _check_async<T: CardTransport + 'static>() {
            assert_async_wallet::<KeycardWallet<T, Error>, Error>();
        }
        fn _check_sync<T: CardTransport + 'static>() {
            assert_sync_wallet::<KeycardWallet<T, Error>, Error>();
        }
        let _ = _check_async::<DummyTransport> as fn();
        let _ = _check_sync::<DummyTransport> as fn();
    }

    #[test]
    fn ephemeral_signing_roundtrip_no_card() {
        // Build a minimal wallet-like ephemeral path without connecting a card:
        // exercise the same software path KeycardWallet uses.
        let codec = Codec::Secp256K1Priv;
        let threshold = NonZero::new(1).unwrap();
        let limit = NonZero::new(1).unwrap();

        require_secp256k1_priv(&codec).unwrap();
        let mut rng = rand_core::OsRng;
        let secret_key = multikey::Builder::new_from_random_bytes(codec, &mut rng)
            .unwrap()
            .with_threshold(threshold)
            .with_limit(limit)
            .try_build()
            .unwrap();
        let public_key = secret_key.conv_view().unwrap().to_public_key().unwrap();
        let data = b"ephemeral plog open";
        let signature = secret_key
            .sign_view()
            .unwrap()
            .sign(data, false, None)
            .unwrap();

        verify_multikey(&public_key, data, &signature).unwrap();
        assert!(public_key.attr_view().unwrap().is_public_key());
    }

    #[test]
    fn ephemeral_rejects_ed25519() {
        let err = require_secp256k1_priv(&Codec::Ed25519Priv).unwrap_err();
        assert!(matches!(err, Error::UnsupportedCodec(_)));
    }

    #[test]
    fn default_pubkey_key_is_pubkey() {
        assert_eq!(default_pubkey_key().to_string(), "/pubkey");
    }

    /// Hardware integration: open plog + update on a real Keycard.
    ///
    /// Requires feature `pcsc`, a paired card, and env vars:
    /// - `KEYCARD_PIN`
    /// - `KEYCARD_PAIRING_KEY` (64 hex chars)
    /// - `KEYCARD_PAIRING_INDEX` (0–99)
    #[cfg(feature = "pcsc")]
    #[tokio::test]
    #[ignore = "requires physical Keycard + KEYCARD_* env vars"]
    async fn hardware_open_and_update_plog() {
        use bs::config::asynchronous::{KeyManager, MultiSigner};
        use bs::ops::params::anykey::PubkeyParams;
        use bs::ops::params::vlad::{FirstEntryKeyParams, VladParams};
        use bs::ops::{open, update};
        use bs::BetterSign;
        use nexum_apdu_transport_pcsc::PcscDeviceManager;
        use provenance_log::key::key_paths::ValidatedKeyParams;
        use provenance_log::{Key, Script};

        let pin = std::env::var("KEYCARD_PIN").expect("KEYCARD_PIN");
        let pairing_hex = std::env::var("KEYCARD_PAIRING_KEY").expect("KEYCARD_PAIRING_KEY");
        let pairing_index: u8 = std::env::var("KEYCARD_PAIRING_INDEX")
            .expect("KEYCARD_PAIRING_INDEX")
            .parse()
            .expect("pairing index");
        let key_bytes = parse_hex32(pairing_hex.trim()).expect("pairing key hex");

        let manager = PcscDeviceManager::new().expect("pcsc manager");
        let readers = manager.list_readers().expect("list readers");
        let reader = readers.first().expect("at least one PC/SC reader");
        let transport = manager
            .open_reader(reader.name())
            .expect("open reader");

        let wallet = KeycardWallet::<_, Error>::with_known_credentials(
            transport,
            pin,
            key_bytes,
            pairing_index,
            None,
        )
        .expect("connect keycard");

        // Type-check BetterSign supertraits on the live instance
        fn use_async<W: KeyManager<Error> + MultiSigner<Error>>(_: &W) {}
        use_async(&wallet);

        let open_cfg = open::Config::builder()
            .vlad(
                VladParams::builder()
                    .codec(Codec::Secp256K1Priv)
                    .build(),
            )
            .first_entry_params(
                FirstEntryKeyParams::builder()
                    .codec(Codec::Secp256K1Priv)
                    .build()
                    .into(),
            )
            .pubkey(
                PubkeyParams::builder()
                    .codec(Codec::Secp256K1Priv)
                    .build()
                    .into(),
            )
            .lock(Script::Code(
                Key::default(),
                r#"check_signature("/pubkey", "/entry/")"#.to_string(),
            ))
            .unlock(Script::Code(
                Key::default(),
                r#"push("/entry/"); push("/entry/proof")"#.to_string(),
            ))
            .build();

        let mut bs = BetterSign::new(&open_cfg, wallet.clone(), wallet)
            .await
            .expect("open plog");
        assert!(
            bs.plog().verify().count() > 0,
            "initial plog should verify"
        );

        let update_cfg = update::Config::builder()
            .unlock(Script::Code(
                Key::default(),
                r#"push("/entry/"); push("/entry/proof")"#.to_string(),
            ))
            .entry_signing_key(PubkeyParams::KEY_PATH.into())
            .build();
        bs.update(update_cfg).await.expect("update plog");
        assert!(
            bs.plog().verify().count() > 0,
            "updated plog should verify"
        );
    }

    #[cfg(feature = "pcsc")]
    fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
        let s = s.trim().strip_prefix("0x").unwrap_or(s);
        if s.len() != 64 {
            return Err(format!("expected 64 hex chars, got {}", s.len()));
        }
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|e| e.to_string())?;
        }
        Ok(out)
    }
}
