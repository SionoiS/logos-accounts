//! Key storage method selection for create/load account.

use crate::Error;
use crate::path_map::DEFAULT_PUBKEY_PATH;
use serde::{Deserialize, Serialize};

/// How long-lived key material is stored for an account.
///
/// Chosen by the caller when creating or importing an account (no separate connect step).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum StorageConfig {
    /// In-process software wallet (primarily for testing / CI).
    Local,
    /// Hardware Keycard. Create requires a virgin card; load needs pairing credentials.
    Keycard {
        /// User PIN (6 digits). Optional on create (generated if absent); required on load.
        #[serde(default)]
        pin: Option<String>,
        /// PUK (12 digits). Optional on create (generated if absent); not used on load.
        #[serde(default)]
        puk: Option<String>,
        /// Pairing password used at INIT. Optional on create (generated if absent).
        #[serde(default)]
        pairing_password: Option<String>,
        /// Pairing key hex (64 chars). Required on load; returned by create.
        #[serde(default)]
        pairing_key_hex: Option<String>,
        /// Pairing slot index (0–99). Required on load; returned by create.
        #[serde(default)]
        pairing_index: Option<u8>,
        /// BIP32 path for `/pubkey` (default [`DEFAULT_PUBKEY_PATH`]).
        #[serde(default)]
        derivation_path: Option<String>,
    },
}

impl StorageConfig {
    /// BIP32 derivation path for `/pubkey`, or the crate default.
    pub fn derivation_path(&self) -> &str {
        match self {
            StorageConfig::Local => DEFAULT_PUBKEY_PATH,
            StorageConfig::Keycard {
                derivation_path, ..
            } => derivation_path.as_deref().unwrap_or(DEFAULT_PUBKEY_PATH),
        }
    }

    /// Whether this config selects local software storage.
    pub fn is_local(&self) -> bool {
        matches!(self, StorageConfig::Local)
    }

    /// Whether this config selects Keycard storage.
    pub fn is_keycard(&self) -> bool {
        matches!(self, StorageConfig::Keycard { .. })
    }
}

/// Parse storage selection JSON.
pub fn parse_storage_json(s: &str) -> Result<StorageConfig, Error> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(Error::Encoding(
            "storage_json is empty; expected {\"method\":\"local\"} or keycard object".into(),
        ));
    }
    serde_json::from_str(trimmed).map_err(|e| Error::Encoding(format!("storage_json: {e}")))
}

/// Credentials returned after Keycard account create (sensitive).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeycardCredentials {
    /// User PIN.
    pub pin: String,
    /// PUK for unblocking.
    pub puk: String,
    /// Pairing password used during INIT (for human backup; loads use pairing_key).
    pub pairing_password: String,
    /// Pairing key hex (64 lowercase hex chars).
    pub pairing_key_hex: String,
    /// Pairing slot index.
    pub pairing_index: u8,
}

/// Account summary plus optional Keycard credentials (create with keycard storage).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateAccountResult {
    /// Multibase VLAD identity.
    pub vlad: String,
    /// Multibase head entry CID.
    pub head_cid: String,
    /// Multibase Multikey public key for `/pubkey` (when available).
    pub pubkey: Option<String>,
    /// Present only when the account was created on a Keycard.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keycard: Option<KeycardCredentials>,
}

impl CreateAccountResult {
    /// Build from a plain account summary (local storage).
    pub fn from_summary(summary: crate::api::AccountSummary) -> Self {
        Self {
            vlad: summary.vlad,
            head_cid: summary.head_cid,
            pubkey: summary.pubkey,
            keycard: None,
        }
    }

    /// Build from summary + keycard credentials.
    pub fn with_keycard(
        summary: crate::api::AccountSummary,
        credentials: KeycardCredentials,
    ) -> Self {
        Self {
            vlad: summary.vlad,
            head_cid: summary.head_cid,
            pubkey: summary.pubkey,
            keycard: Some(credentials),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_local() {
        let c = parse_storage_json(r#"{"method":"local"}"#).unwrap();
        assert!(c.is_local());
        assert_eq!(c.derivation_path(), DEFAULT_PUBKEY_PATH);
    }

    #[test]
    fn parse_keycard_create_partial() {
        let c = parse_storage_json(
            r#"{"method":"keycard","pin":"123456","derivation_path":"m/44'/60'/0'/0/1"}"#,
        )
        .unwrap();
        match c {
            StorageConfig::Keycard {
                pin,
                pairing_key_hex,
                derivation_path,
                ..
            } => {
                assert_eq!(pin.as_deref(), Some("123456"));
                assert!(pairing_key_hex.is_none());
                assert_eq!(derivation_path.as_deref(), Some("m/44'/60'/0'/0/1"));
            }
            _ => panic!("expected keycard"),
        }
    }

    #[test]
    fn parse_keycard_load() {
        let c = parse_storage_json(
            r#"{"method":"keycard","pin":"123456","pairing_key_hex":"aa","pairing_index":1}"#,
        )
        .unwrap();
        assert!(c.is_keycard());
    }

    #[test]
    fn parse_empty_fails() {
        assert!(parse_storage_json("").is_err());
    }
}
