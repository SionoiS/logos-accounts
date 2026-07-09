//! Maps provenance-log logical keys (`/pubkey`, …) to BIP32 derivation paths on the card.

use crate::error::{lock_err, Error};
use bip32::DerivationPath;
use provenance_log::Key;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Mutex;

/// Default BIP32 path for the long-lived advertised `/pubkey` on Keycard.
pub const DEFAULT_PUBKEY_PATH: &str = "m/44'/60'/0'/0/0";

/// Thread-safe map from logical plog key paths to BIP32 derivation paths.
#[derive(Debug, Default)]
pub struct PathMap {
    inner: Mutex<HashMap<Key, DerivationPath>>,
}

impl PathMap {
    /// Empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Map with `/pubkey` registered to `default_derivation` (or [`DEFAULT_PUBKEY_PATH`]).
    pub fn with_default_pubkey(default_derivation: Option<&str>) -> Result<Self, Error> {
        let map = Self::new();
        let path = parse_derivation_path(default_derivation.unwrap_or(DEFAULT_PUBKEY_PATH))?;
        let key = Key::try_from("/pubkey").map_err(|e| Error::Message(e.to_string()))?;
        map.register(key, path)?;
        Ok(map)
    }

    /// Register or overwrite a logical key → BIP32 path mapping.
    pub fn register(&self, key: Key, path: DerivationPath) -> Result<(), Error> {
        let mut guard = self.inner.lock().map_err(lock_err)?;
        guard.insert(key, path);
        Ok(())
    }

    /// Register from a BIP32 path string.
    pub fn register_str(&self, key: Key, path: &str) -> Result<(), Error> {
        self.register(key, parse_derivation_path(path)?)
    }

    /// Look up the BIP32 path for a logical key.
    pub fn get(&self, key: &Key) -> Result<Option<DerivationPath>, Error> {
        let guard = self.inner.lock().map_err(lock_err)?;
        Ok(guard.get(key).cloned())
    }

    /// Require a registered path or return [`Error::PathNotRegistered`].
    pub fn require(&self, key: &Key) -> Result<DerivationPath, Error> {
        self.get(key)?
            .ok_or_else(|| Error::PathNotRegistered(key.clone()))
    }

    /// Remove a mapping; returns the previous path if any.
    pub fn remove(&self, key: &Key) -> Result<Option<DerivationPath>, Error> {
        let mut guard = self.inner.lock().map_err(lock_err)?;
        Ok(guard.remove(key))
    }

    /// Number of registered paths.
    pub fn len(&self) -> Result<usize, Error> {
        let guard = self.inner.lock().map_err(lock_err)?;
        Ok(guard.len())
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> Result<bool, Error> {
        Ok(self.len()? == 0)
    }
}

/// Parse a BIP32 derivation path string.
pub fn parse_derivation_path(s: &str) -> Result<DerivationPath, Error> {
    DerivationPath::from_str(s).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pubkey_mapping() {
        let map = PathMap::with_default_pubkey(None).unwrap();
        let key = Key::try_from("/pubkey").unwrap();
        let path = map.require(&key).unwrap();
        assert_eq!(path.to_string(), DEFAULT_PUBKEY_PATH);
    }

    #[test]
    fn unmapped_path_errors() {
        let map = PathMap::new();
        let key = Key::try_from("/unknown").unwrap();
        let err = map.require(&key).unwrap_err();
        assert!(matches!(err, Error::PathNotRegistered(_)));
    }

    #[test]
    fn register_and_remove() {
        let map = PathMap::new();
        let key = Key::try_from("/recoverykey").unwrap();
        map.register_str(key.clone(), "m/44'/60'/0'/0/1").unwrap();
        assert_eq!(
            map.require(&key).unwrap().to_string(),
            "m/44'/60'/0'/0/1"
        );
        map.remove(&key).unwrap();
        assert!(map.get(&key).unwrap().is_none());
    }
}
