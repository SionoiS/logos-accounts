//! Domain API: IPC-friendly single-account service surface for BetterSign accounts.
//!
//! Key storage is selected when creating or loading an account (local software
//! wallet or Keycard). The Logos module layers a multi-account [`crate::AccountCache`]
//! on top; this type remains one wallet + one p-log. Create/load verify the p-log
//! chain before the account is considered loaded; path reads use [`AccountsApi::get_value`].

use crate::config::{default_open_config, default_update_config, update_config_with_ops};
use crate::encoding::{
    decode_bytes_multibase, decode_hex32, decode_plog, encode_bytes_multibase, encode_cid,
    encode_multikey, encode_plog, encode_vlad, plog_from_bytes, plog_to_bytes,
};
use crate::keycard_lifecycle::{
    initialize_virgin_keycard, open_and_verify_binding, store_vlad_binding, KeycardCreateSecrets,
};
use crate::path_map::DEFAULT_PUBKEY_PATH;
use crate::storage::CreateAccountResult;
use crate::wallet::{default_pubkey_key, KeycardWallet};
use crate::Error;
use bs::config::asynchronous::{KeyManager, MultiSigner};
use bs::ops::update::OpParams;
use bs::BetterSign;
use multicodec::Codec;
use multikey::Multikey;
use nexum_apdu_core::prelude::CardTransport;
use provenance_log::{Key, Log, Value};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::path::PathBuf;

/// Summary returned by create/load/update — LIDL-friendly strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSummary {
    /// Multibase VLAD identity.
    pub vlad: String,
    /// Multibase head entry CID.
    pub head_cid: String,
    /// Multibase Multikey public key for `/pubkey` when present in the p-log KVP.
    pub pubkey: Option<String>,
}

/// Value at a logical p-log key path after full-chain verification.
///
/// Serializes as `{"type":"str","value":"..."}` or `{"type":"bin","value":"<multibase>"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum PlogPathValue {
    /// UTF-8 string stored via `use_str` (or equivalent).
    Str(String),
    /// Binary blob (multibase). Multikey-shaped data uses Multikey multibase encoding.
    Bin(String),
}

impl PlogPathValue {
    /// Serialize to the JSON string used on the LIDL boundary.
    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| {
            serde_json::json!({ "error": e.to_string() }).to_string()
        })
    }
}

/// Full-chain verify; error if any entry fails or the log has no entries.
pub fn ensure_plog_verified(log: &Log) -> Result<(), Error> {
    let mut any = false;
    for item in log.verify() {
        any = true;
        if let Err(e) = item {
            return Err(Error::PlogVerifyFailed(e.to_string()));
        }
    }
    if !any {
        return Err(Error::PlogVerifyFailed("empty provenance log".into()));
    }
    Ok(())
}

/// Read a path from the verified head KVP of `log`.
///
/// Re-verifies the full chain (cheap for small logs; enforces integrity on read).
pub fn get_plog_value(log: &Log, path: &str) -> Result<PlogPathValue, Error> {
    let key = parse_key(path)?;
    let mut last: Option<provenance_log::Kvp<'_>> = None;
    let mut any = false;
    for item in log.verify() {
        any = true;
        match item {
            Ok((_count, _entry, kvp)) => last = Some(kvp),
            Err(e) => return Err(Error::PlogVerifyFailed(e.to_string())),
        }
    }
    if !any {
        return Err(Error::PlogVerifyFailed("empty provenance log".into()));
    }
    let kvp = last.expect("any implies last");
    for (k, v) in kvp.iter() {
        if k == &key {
            return Ok(match v {
                Value::Str(s) => PlogPathValue::Str(s.clone()),
                Value::Data(b) => PlogPathValue::Bin(encode_bin_value(b)),
                Value::Nil => PlogPathValue::Bin(encode_bytes_multibase(&[])),
            });
        }
    }
    Err(Error::PathNotFound(path.to_string()))
}

fn encode_bin_value(data: &[u8]) -> String {
    match Multikey::try_from(data) {
        Ok(mk) => encode_multikey(&mk),
        Err(_) => encode_bytes_multibase(data),
    }
}

fn summary_from_verified_plog(log: &Log) -> Result<AccountSummary, Error> {
    ensure_plog_verified(log)?;
    let pubkey = match get_plog_value(log, "/pubkey") {
        Ok(PlogPathValue::Bin(s)) => Some(s),
        Ok(PlogPathValue::Str(s)) => Some(s),
        Err(Error::PathNotFound(_)) => None,
        Err(e) => return Err(e),
    };
    Ok(AccountSummary {
        vlad: encode_vlad(&log.vlad),
        head_cid: encode_cid(&log.head),
        pubkey,
    })
}

/// Serializable account ops for `update_account` (maps to BetterSign `OpParams`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum AccountOp {
    /// No-op at a key path.
    Noop {
        /// Logical key path.
        key: String,
    },
    /// Delete a key path.
    Delete {
        /// Logical key path.
        key: String,
    },
    /// Store a UTF-8 string value.
    UseStr {
        /// Logical key path.
        key: String,
        /// String value.
        value: String,
    },
    /// Store binary data (multibase-encoded).
    UseBin {
        /// Logical key path.
        key: String,
        /// Multibase payload.
        data_multibase: String,
    },
}

impl AccountOp {
    /// Convert to BetterSign [`OpParams`].
    pub fn into_op_params(self) -> Result<OpParams, Error> {
        match self {
            AccountOp::Noop { key } => Ok(OpParams::Noop {
                key: parse_key(&key)?,
            }),
            AccountOp::Delete { key } => Ok(OpParams::Delete {
                key: parse_key(&key)?,
            }),
            AccountOp::UseStr { key, value } => Ok(OpParams::UseStr {
                key: parse_key(&key)?,
                s: value,
            }),
            AccountOp::UseBin {
                key,
                data_multibase,
            } => Ok(OpParams::UseBin {
                key: parse_key(&key)?,
                data: decode_bytes_multibase(&data_multibase)?,
            }),
        }
    }
}

/// Parse JSON array of [`AccountOp`]s.
pub fn parse_ops_json(ops_json: &str) -> Result<Vec<OpParams>, Error> {
    if ops_json.trim().is_empty() || ops_json.trim() == "[]" {
        return Ok(Vec::new());
    }
    let ops: Vec<AccountOp> =
        serde_json::from_str(ops_json).map_err(|e| Error::Encoding(e.to_string()))?;
    ops.into_iter().map(AccountOp::into_op_params).collect()
}

fn parse_key(s: &str) -> Result<Key, Error> {
    Key::try_from(s).map_err(|e| Error::InvalidOp(format!("invalid key path {s}: {e}")))
}

/// IPC-friendly accounts service.
///
/// Holds an optional wallet and an optional open BetterSign account.
/// Generics stay inside the library; callers use multibase strings / JSON.
///
/// # Type parameter
///
/// `W` is typically [`KeycardWallet`]`<T>` or `bs_wallets::memory::InMemoryKeyManager<Error>`
/// for software integration tests.
pub struct AccountsApi<W> {
    wallet: Option<W>,
    account: Option<BetterSign<W, W, Error>>,
    /// Optional filesystem root for Phase 3 persistence (pairing / plog export).
    persistence_path: Option<PathBuf>,
    /// BIP32 derivation currently intended for `/pubkey`.
    pubkey_derivation: String,
}

impl<W> Default for AccountsApi<W> {
    fn default() -> Self {
        Self::new()
    }
}

impl<W> std::fmt::Debug for AccountsApi<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountsApi")
            .field("connected", &self.wallet.is_some())
            .field("has_account", &self.account.is_some())
            .field("persistence_path", &self.persistence_path)
            .field("pubkey_derivation", &self.pubkey_derivation)
            .finish()
    }
}

impl<W> AccountsApi<W> {
    /// Empty API (not connected, no account).
    pub fn new() -> Self {
        Self {
            wallet: None,
            account: None,
            persistence_path: None,
            pubkey_derivation: DEFAULT_PUBKEY_PATH.to_string(),
        }
    }

    /// Set a persistence directory hint for Phase 3 (pairing material, last plog).
    ///
    /// Phase 2 does not write files automatically; callers may use this path.
    pub fn with_persistence_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.persistence_path = Some(path.into());
        self
    }

    /// Persistence path if configured.
    pub fn persistence_path(&self) -> Option<&PathBuf> {
        self.persistence_path.as_ref()
    }

    /// BIP32 path mapped (or to be mapped) to `/pubkey`.
    pub fn pubkey_derivation(&self) -> &str {
        &self.pubkey_derivation
    }

    /// Whether a wallet is attached.
    pub fn is_connected(&self) -> bool {
        self.wallet.is_some()
    }

    /// Whether an account (plog) is loaded.
    pub fn has_account(&self) -> bool {
        self.account.is_some()
    }

    /// Attach a pre-built wallet (software tests, custom session).
    pub fn attach_wallet(&mut self, wallet: W, pubkey_derivation: Option<&str>) {
        if let Some(d) = pubkey_derivation {
            self.pubkey_derivation = d.to_string();
        }
        self.wallet = Some(wallet);
        self.account = None;
    }

    /// Take the wallet out (disconnect), dropping any loaded account.
    pub fn disconnect(&mut self) -> Option<W> {
        self.account = None;
        self.wallet.take()
    }

    fn require_wallet_ref(&self) -> Result<&W, Error> {
        self.wallet.as_ref().ok_or(Error::NotConnected)
    }

    fn require_account_ref(&self) -> Result<&BetterSign<W, W, Error>, Error> {
        self.account.as_ref().ok_or(Error::NoAccount)
    }

    fn require_account_mut(&mut self) -> Result<&mut BetterSign<W, W, Error>, Error> {
        self.account.as_mut().ok_or(Error::NoAccount)
    }
}

impl<W> AccountsApi<W>
where
    W: Clone + KeyManager<Error> + MultiSigner<Error>,
{
    /// Create a new account: open a provenance log with default secp256k1 config.
    ///
    /// The wallet is cloned into BetterSign (Arc-backed for both Keycard and software
    /// backends), so the API remains connected on success or failure. The opened log is
    /// verified before this method returns.
    pub async fn create_account(&mut self) -> Result<AccountSummary, Error> {
        let wallet = self.require_wallet_ref()?.clone();
        let open_cfg = default_open_config();
        let bs = BetterSign::new(&open_cfg, wallet.clone(), wallet.clone()).await?;
        let summary = summary_from_verified_plog(bs.plog())?;
        self.account = Some(bs);
        Ok(summary)
    }

    /// Load an existing account from multibase plog encoding.
    ///
    /// The log must pass full-chain verification or load fails (nothing is stored).
    pub async fn load_account(&mut self, plog_multibase: &str) -> Result<AccountSummary, Error> {
        let log = decode_plog(plog_multibase)?;
        self.load_account_log(log).await
    }

    /// Load an existing account from raw plog bytes.
    ///
    /// The log must pass full-chain verification or load fails (nothing is stored).
    pub async fn load_account_bytes(&mut self, plog_bytes: &[u8]) -> Result<AccountSummary, Error> {
        let log = plog_from_bytes(plog_bytes)?;
        self.load_account_log(log).await
    }

    async fn load_account_log(&mut self, log: Log) -> Result<AccountSummary, Error> {
        let summary = summary_from_verified_plog(&log)?;
        let wallet = self.require_wallet_ref()?.clone();
        self.account = Some(BetterSign::from_parts(log, wallet.clone(), wallet));
        Ok(summary)
    }

    /// Append an update entry. `ops_json` is a JSON array of [`AccountOp`] (or empty / `[]`).
    pub async fn update_account(&mut self, ops_json: &str) -> Result<AccountSummary, Error> {
        let ops = parse_ops_json(ops_json)?;
        self.update_account_ops(ops).await
    }

    /// Append an update entry with typed ops.
    pub async fn update_account_ops(
        &mut self,
        ops: Vec<OpParams>,
    ) -> Result<AccountSummary, Error> {
        let cfg = if ops.is_empty() {
            default_update_config()
        } else {
            update_config_with_ops(ops)
        };
        let account = self.require_account_mut()?;
        account.update(cfg).await?;
        summary_from_verified_plog(self.require_account_ref()?.plog())
    }

    /// Multibase VLAD of the loaded account.
    pub fn vlad(&self) -> Result<String, Error> {
        Ok(encode_vlad(&self.require_account_ref()?.plog().vlad))
    }

    /// Read a logical key path from the loaded p-log's verified KVP state.
    ///
    /// Examples: `"/pubkey"`, `"/profile/name"`. Presence in a loaded account implies the
    /// log was verified at create/load; this re-checks the chain while materializing state.
    pub fn get_value(&self, path: &str) -> Result<PlogPathValue, Error> {
        let log = self.require_account_ref()?.plog();
        get_plog_value(log, path)
    }

    /// Export the loaded plog as multibase.
    pub fn export_plog(&self) -> Result<String, Error> {
        Ok(encode_plog(self.require_account_ref()?.plog()))
    }

    /// Export the loaded plog as raw bytes.
    pub fn export_plog_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(plog_to_bytes(self.require_account_ref()?.plog()))
    }

    /// Borrow the loaded provenance log.
    pub fn plog(&self) -> Result<&Log, Error> {
        Ok(self.require_account_ref()?.plog())
    }

    /// Borrow the wallet.
    pub fn wallet(&self) -> Result<&W, Error> {
        self.require_wallet_ref()
    }

    /// Mutable wallet (e.g. path rebinding before rotation).
    pub fn wallet_mut(&mut self) -> Result<&mut W, Error> {
        self.wallet.as_mut().ok_or(Error::NotConnected)
    }
}

// --- Keycard-specific helpers ---

impl<T> AccountsApi<KeycardWallet<T>>
where
    T: CardTransport + 'static,
{
    /// Create an account on a **virgin** Keycard: INIT → pair → GENERATE KEY → open p-log →
    /// store VLAD hash on the card.
    ///
    /// Returns the API with wallet + account loaded, plus credentials for later loads.
    pub async fn create_account_on_virgin_keycard(
        transport: T,
        secrets: KeycardCreateSecrets,
        pubkey_derivation: Option<&str>,
    ) -> Result<(Self, CreateAccountResult), Error> {
        let initialized =
            initialize_virgin_keycard(transport, secrets, pubkey_derivation)?;
        let derivation = initialized.derivation_path.clone();
        let (wallet, credentials) = initialized.into_wallet()?;

        let mut api = Self::new();
        api.attach_wallet(wallet, Some(&derivation));
        let summary = api.create_account().await?;

        // Bind card to this VLAD (fail the whole operation if store fails).
        let vlad = api.require_account_ref()?.plog().vlad.clone();
        {
            let wallet = api.require_wallet_ref()?;
            store_vlad_binding(wallet.session(), &vlad).await?;
        }

        let result = CreateAccountResult::with_keycard(summary, credentials);
        Ok((api, result))
    }

    /// Load a p-log on a Keycard after verifying the on-card VLAD hash matches.
    pub async fn load_account_on_keycard(
        transport: T,
        plog_multibase: &str,
        pin: impl Into<String>,
        pairing_key_hex: &str,
        pairing_index: u8,
        pubkey_derivation: Option<&str>,
    ) -> Result<Self, Error> {
        let log = decode_plog(plog_multibase)?;
        let pairing_key = decode_hex32(pairing_key_hex)?;
        let wallet = open_and_verify_binding(
            transport,
            pin,
            pairing_key,
            pairing_index,
            &log.vlad,
            pubkey_derivation,
        )
        .await?;

        let mut api = Self::new();
        api.attach_wallet(wallet, pubkey_derivation);
        api.load_account_log(log).await?;
        Ok(api)
    }

    /// Rotate `/pubkey` to a new BIP32 path: rebind, export, and commit via plog update.
    ///
    /// Requires a loaded account. Policy: revoke previous `/pubkey` in the log and
    /// KeyGen a fresh one from the wallet (Keycard export at the new path).
    pub async fn rotate_pubkey(&mut self, new_derivation: &str) -> Result<AccountSummary, Error> {
        if self.account.is_none() {
            return Err(Error::NoAccount);
        }
        let key = default_pubkey_key();
        {
            let wallet = self.require_wallet_ref()?;
            wallet.rebind_path(key.clone(), new_derivation)?;
        }
        self.pubkey_derivation = new_derivation.to_string();

        let thr = NonZeroUsize::new(1).unwrap();
        let ops = vec![OpParams::KeyGen {
            key: key.clone(),
            codec: Codec::Secp256K1Priv,
            threshold: thr,
            limit: thr,
            revoke: true,
        }];
        self.update_account_ops(ops).await
    }
}

/// Convenience: software wallet type used in integration tests.
pub type SoftwareWallet = bs_wallets::memory::InMemoryKeyManager<Error>;

/// Accounts API with software in-memory wallet (no card).
pub type SoftwareAccountsApi = AccountsApi<SoftwareWallet>;

impl SoftwareAccountsApi {
    /// Build API pre-connected to a fresh in-memory wallet (secp256k1 only in practice).
    pub fn software() -> Self {
        let mut api = Self::new();
        api.attach_wallet(SoftwareWallet::new(), Some(DEFAULT_PUBKEY_PATH));
        api
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::decode_multikey;
    use multikey::Views;

    #[tokio::test]
    async fn create_update_export_import_get_value() {
        let mut api = SoftwareAccountsApi::software();
        assert!(api.is_connected());
        assert!(!api.has_account());

        let created = api.create_account().await.expect("create_account");
        assert!(!created.vlad.is_empty());
        assert!(!created.head_cid.is_empty());
        assert!(created.pubkey.is_some());

        let pk = api.get_value("/pubkey").expect("get /pubkey");
        assert!(matches!(pk, PlogPathValue::Bin(_)));
        assert_eq!(
            match &pk {
                PlogPathValue::Bin(s) => s.as_str(),
                _ => unreachable!(),
            },
            created.pubkey.as_deref().unwrap()
        );

        let updated = api
            .update_account(
                r#"[{"op":"use_str","key":"/profile/name","value":"alice"}]"#,
            )
            .await
            .expect("update");
        assert_ne!(updated.head_cid, created.head_cid);

        assert_eq!(
            api.get_value("/profile/name").unwrap(),
            PlogPathValue::Str("alice".into())
        );

        let exported = api.export_plog().expect("export");
        let exported_bytes = api.export_plog_bytes().expect("export bytes");

        // Import into a fresh software API: load requires full-chain verify.
        let mut api2 = SoftwareAccountsApi::software();
        let loaded = api2
            .load_account(&exported)
            .await
            .expect("load multibase");
        assert_eq!(loaded.vlad, created.vlad);
        assert_eq!(loaded.head_cid, updated.head_cid);
        assert_eq!(
            api2.get_value("/profile/name").unwrap(),
            PlogPathValue::Str("alice".into())
        );

        let loaded_b = {
            let mut api3 = SoftwareAccountsApi::software();
            api3.load_account_bytes(&exported_bytes)
                .await
                .expect("load bytes")
        };
        assert_eq!(loaded_b.vlad, created.vlad);
    }

    #[tokio::test]
    async fn load_rejects_unverified_plog() {
        let mut api = SoftwareAccountsApi::software();
        let created = api.create_account().await.unwrap();
        let exported = api.export_plog().unwrap();
        // Corrupt multibase payload so decode may succeed or fail; if decode
        // succeeds with garbage bytes, verification must fail.
        let mut corrupt_bytes = exported.clone().into_bytes();
        // Flip a character in the middle of the payload (keep multibase prefix).
        let mid = corrupt_bytes.len() / 2;
        if let Some(b) = corrupt_bytes.get_mut(mid) {
            *b = if *b == b'A' { b'B' } else { b'A' };
        }
        let corrupt = String::from_utf8_lossy(&corrupt_bytes).into_owned();
        let mut api2 = SoftwareAccountsApi::software();
        let err = api2.load_account(&corrupt).await;
        assert!(err.is_err(), "corrupt plog should not load; got {err:?}");
        assert!(!api2.has_account());
        // Valid log still loads.
        let loaded = api2.load_account(&exported).await.unwrap();
        assert_eq!(loaded.vlad, created.vlad);
    }

    #[tokio::test]
    async fn get_value_missing_path() {
        let mut api = SoftwareAccountsApi::software();
        api.create_account().await.unwrap();
        let err = api.get_value("/does/not/exist").unwrap_err();
        assert!(matches!(err, Error::PathNotFound(_)), "{err:?}");
    }

    #[tokio::test]
    async fn ops_json_and_not_connected() {
        let mut api = SoftwareAccountsApi::new();
        assert!(matches!(
            api.create_account().await.err(),
            Some(Error::NotConnected)
        ));

        let ops = parse_ops_json(
            r#"[
              {"op":"use_str","key":"/a","value":"b"},
              {"op":"delete","key":"/old"},
              {"op":"use_bin","key":"/bin","data_multibase":"uAQID"}
            ]"#,
        )
        .expect("parse ops");
        assert_eq!(ops.len(), 3);
    }

    #[tokio::test]
    async fn entry_proofs_pubkey_from_plog() {
        let mut api = SoftwareAccountsApi::software();
        let created = api.create_account().await.unwrap();
        let pubkey_mb = created.pubkey.expect("pubkey");
        let pk = decode_multikey(&pubkey_mb).unwrap();
        assert!(pk.attr_view().unwrap().is_public_key());

        api.update_account("[]").await.unwrap();
        match api.get_value("/pubkey").unwrap() {
            PlogPathValue::Bin(s) => assert_eq!(s, pubkey_mb),
            other => panic!("expected bin pubkey, got {other:?}"),
        }
    }
}
