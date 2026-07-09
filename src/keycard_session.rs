//! Keycard session lifecycle: wrap a connected card for exclusive use.

use crate::Error;
use bip32::DerivationPath;
use nexum_apdu_core::prelude::{CardExecutor, CardTransport};
use nexum_keycard::{ExportOption, Keycard, KeycardSecureChannel, PairingInfo};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Shared, exclusively locked Keycard session.
///
/// Mirrors the `Arc<Mutex<Keycard<…>>>` pattern from `nexum-keycard-signer`.
pub type SharedKeycard<T> =
    Arc<Mutex<Keycard<CardExecutor<KeycardSecureChannel<T>>>>>;

/// Session handle holding credentials-backed Keycard access.
pub struct KeycardSession<T: CardTransport> {
    card: SharedKeycard<T>,
}

impl<T: CardTransport> Clone for KeycardSession<T> {
    fn clone(&self) -> Self {
        Self {
            card: Arc::clone(&self.card),
        }
    }
}

impl<T: CardTransport> std::fmt::Debug for KeycardSession<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeycardSession").finish_non_exhaustive()
    }
}

impl<T> KeycardSession<T>
where
    T: CardTransport + 'static,
{
    /// Wrap an existing shared card handle.
    pub fn from_shared(card: SharedKeycard<T>) -> Self {
        Self { card }
    }

    /// Build a session from transport + known PIN / pairing material.
    ///
    /// Follows `KeycardSigner::with_known_credentials`.
    pub fn with_known_credentials(
        transport: T,
        pin: impl Into<String>,
        pairing_key: [u8; 32],
        pairing_index: u8,
    ) -> Result<Self, Error> {
        let pairing_info = PairingInfo {
            key: pairing_key,
            index: pairing_index,
        };
        let keycard = Keycard::with_known_credentials(transport, pin.into(), pairing_info)?;
        Ok(Self {
            card: Arc::new(Mutex::new(keycard)),
        })
    }

    /// Shared card handle (for advanced use / cloning into signers).
    pub fn card(&self) -> &SharedKeycard<T> {
        &self.card
    }

    /// Export the public key at `path` (card I/O).
    pub async fn export_public_key(&self, path: &DerivationPath) -> Result<k256::PublicKey, Error> {
        let mut card = self.card.lock().await;
        let exported = card.export_key(ExportOption::PublicKeyOnly, path)?;
        exported
            .public_key()
            .cloned()
            .ok_or_else(|| Error::UnexpectedExport("missing public key in export".into()))
    }

    /// Sign a 32-byte prehash at `path` (card I/O). `confirm` is forced false for automation.
    pub async fn sign_prehash(
        &self,
        prehash: &[u8; 32],
        path: &DerivationPath,
    ) -> Result<alloy_primitives::Signature, Error> {
        let mut card = self.card.lock().await;
        Ok(card.sign(prehash, path, false)?)
    }

    /// Blocking variants used by sync trait impls.
    pub fn export_public_key_blocking(
        &self,
        path: &DerivationPath,
    ) -> Result<k256::PublicKey, Error> {
        block_on_card(self.card.as_ref(), |card| {
            let exported = card.export_key(ExportOption::PublicKeyOnly, path)?;
            exported
                .public_key()
                .cloned()
                .ok_or_else(|| Error::UnexpectedExport("missing public key in export".into()))
        })
    }

    /// Blocking sign of a 32-byte prehash.
    pub fn sign_prehash_blocking(
        &self,
        prehash: &[u8; 32],
        path: &DerivationPath,
    ) -> Result<alloy_primitives::Signature, Error> {
        block_on_card(self.card.as_ref(), |card| Ok(card.sign(prehash, path, false)?))
    }

    /// Query application status (PIN retries, key initialized, …).
    pub async fn get_status(&self) -> Result<nexum_keycard::ApplicationStatus, Error> {
        let mut card = self.card.lock().await;
        Ok(card.get_status()?)
    }

    /// Re-select the Keycard applet and return application info (key UID, version, …).
    pub async fn application_info(&self) -> Result<nexum_keycard::ApplicationInfo, Error> {
        let mut card = self.card.lock().await;
        Ok(card.select_keycard()?)
    }
}

/// Run work against a tokio mutex without requiring a running async runtime
/// when the lock is free (`futures::executor::block_on`).
fn block_on_card<T, R, F>(mutex: &tokio::sync::Mutex<T>, f: F) -> Result<R, Error>
where
    F: FnOnce(&mut T) -> Result<R, Error>,
{
    let mut guard = futures::executor::block_on(mutex.lock());
    f(&mut guard)
}
