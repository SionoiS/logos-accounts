//! Virgin Keycard initialization bound to account creation.
//!
//! Create path: SELECT → virgin check → INIT → refresh → pair → secure channel →
//! GENERATE KEY → (caller opens p-log) → store VLAD hash on card.

use crate::binding::vlad_hash;
use crate::encoding::encode_hex;
use crate::error::Error;
use crate::keycard_session::{KeycardSession, SharedKeycard};
use crate::path_map::DEFAULT_PUBKEY_PATH;
use crate::storage::KeycardCredentials;
use crate::wallet::KeycardWallet;
use multicid::Vlad;
use nexum_apdu_core::prelude::CardTransport;
use nexum_keycard::{
    ApplicationInfo, Keycard, KeycardSecureChannel, PairingInfo, Secrets,
};
use nexum_apdu_core::prelude::CardExecutor;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Result of initializing a virgin Keycard for account creation.
pub struct InitializedKeycard<T: CardTransport> {
    /// Session ready for signing / public data I/O.
    pub session: KeycardSession<T>,
    /// Credentials the caller must persist for later loads.
    pub credentials: KeycardCredentials,
    /// BIP32 path mapped to `/pubkey`.
    pub derivation_path: String,
}

/// Optional secrets supplied at create; missing fields are generated.
#[derive(Debug, Clone, Default)]
pub struct KeycardCreateSecrets {
    /// Optional PIN (6 digits).
    pub pin: Option<String>,
    /// Optional PUK (12 digits).
    pub puk: Option<String>,
    /// Optional pairing password.
    pub pairing_password: Option<String>,
}

fn build_secrets(opts: &KeycardCreateSecrets) -> Result<Secrets, Error> {
    match (
        opts.pin.as_deref(),
        opts.puk.as_deref(),
        opts.pairing_password.as_deref(),
    ) {
        (Some(pin), Some(puk), Some(pass)) => Ok(Secrets::new(pin, puk, pass)),
        (None, None, None) => Ok(Secrets::generate()),
        (pin, puk, pass) => {
            // Mix of provided and missing: fill gaps from a full generate.
            let generated = Secrets::generate();
            let pin = pin
                .map(str::to_string)
                .unwrap_or_else(|| generated.pin().to_string());
            let puk = puk
                .map(str::to_string)
                .unwrap_or_else(|| generated.puk().to_string());
            let pass = pass
                .map(str::to_string)
                .unwrap_or_else(|| generated.pairing_pass().to_string());
            Ok(Secrets::new(&pin, &puk, &pass))
        }
    }
}

/// True when SELECT produced the synthetic uninitialized ApplicationInfo.
fn is_virgin_app_info(info: &ApplicationInfo) -> bool {
    info.key_uid.is_none() && info.instance_uid == [0u8; 16]
}

/// Initialize a virgin Keycard: INIT, pair, open channel, GENERATE KEY.
///
/// Returns a session ready for `KeycardWallet` construction and VLAD-hash storage.
pub fn initialize_virgin_keycard<T>(
    transport: T,
    secrets_opts: KeycardCreateSecrets,
    derivation_path: Option<&str>,
) -> Result<InitializedKeycard<T>, Error>
where
    T: CardTransport + 'static,
{
    let secrets = build_secrets(&secrets_opts)?;
    let pin = secrets.pin().to_string();
    let puk = secrets.puk().to_string();
    let pairing_password = secrets.pairing_pass().to_string();
    let derivation = derivation_path
        .unwrap_or(DEFAULT_PUBKEY_PATH)
        .to_string();

    let pin_for_cb = pin.clone();
    let pass_for_cb = pairing_password.clone();
    let input = Box::new(move |prompt: &str| -> nexum_keycard::Result<String> {
        let p = prompt.to_lowercase();
        if p.contains("pairing") {
            Ok(pass_for_cb.clone())
        } else {
            Ok(pin_for_cb.clone())
        }
    });
    let confirm = Box::new(|_: &str| -> nexum_keycard::Result<bool> { Ok(true) });

    let mut keycard: Keycard<CardExecutor<KeycardSecureChannel<T>>> =
        Keycard::from_interactive(transport, input, confirm, Some(pin.clone()), None)
            .map_err(Error::from)?;

    // Virgin check from SELECT at construction.
    let app_info = keycard
        .select_keycard()
        .map_err(Error::from)?;
    if !is_virgin_app_info(&app_info) {
        return Err(Error::KeycardNotVirgin(format!(
            "card already initialized or has keys (key_uid present: {}, instance_uid non-zero: {})",
            app_info.key_uid.is_some(),
            app_info.instance_uid != [0u8; 16]
        )));
    }

    keycard
        .initialize(&secrets, false)
        .map_err(|e| {
            if matches!(e, nexum_keycard::Error::AlreadyInitialized) {
                Error::KeycardNotVirgin(e.to_string())
            } else {
                Error::from(e)
            }
        })?;

    keycard.refresh_after_init().map_err(Error::from)?;

    let pairing_info: PairingInfo = keycard.pair().map_err(Error::from)?;
    keycard.open_secure_channel().map_err(Error::from)?;
    let _key_uid = keycard.generate_key(false).map_err(Error::from)?;

    let credentials = KeycardCredentials {
        pin,
        puk,
        pairing_password,
        pairing_key_hex: encode_hex(&pairing_info.key),
        pairing_index: pairing_info.index,
    };

    let session = KeycardSession::from_shared(Arc::new(Mutex::new(keycard)));

    Ok(InitializedKeycard {
        session,
        credentials,
        derivation_path: derivation,
    })
}

impl<T> InitializedKeycard<T>
where
    T: CardTransport + 'static,
{
    /// Build a [`KeycardWallet`] from this initialized session.
    pub fn into_wallet(self) -> Result<(KeycardWallet<T>, KeycardCredentials), Error> {
        let derivation = self.derivation_path.clone();
        let credentials = self.credentials;
        let wallet = KeycardWallet::new(self.session, Some(&derivation))?;
        Ok((wallet, credentials))
    }

    /// Shared card handle.
    pub fn shared_card(&self) -> SharedKeycard<T> {
        self.session.card().clone()
    }
}

/// Store the VLAD binding hash on the card public record.
pub async fn store_vlad_binding<T>(session: &KeycardSession<T>, vlad: &Vlad) -> Result<(), Error>
where
    T: CardTransport + 'static,
{
    let hash = vlad_hash(vlad);
    session.store_public_data(&hash).await
}

/// Read and verify the VLAD binding on the card against `vlad`.
pub async fn verify_vlad_binding<T>(session: &KeycardSession<T>, vlad: &Vlad) -> Result<(), Error>
where
    T: CardTransport + 'static,
{
    let data = session.get_public_data().await?;
    crate::binding::verify_card_vlad_binding(&data, vlad)
}

/// Open a known-credentials session and verify VLAD hash matches the p-log.
pub async fn open_and_verify_binding<T>(
    transport: T,
    pin: impl Into<String>,
    pairing_key: [u8; 32],
    pairing_index: u8,
    vlad: &Vlad,
    derivation_path: Option<&str>,
) -> Result<KeycardWallet<T>, Error>
where
    T: CardTransport + 'static,
{
    let wallet = KeycardWallet::with_known_credentials(
        transport,
        pin,
        pairing_key,
        pairing_index,
        derivation_path,
    )?;
    verify_vlad_binding(wallet.session(), vlad).await?;
    Ok(wallet)
}


