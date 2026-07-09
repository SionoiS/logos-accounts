//! In-process multi-account cache keyed by VLAD hash.
//!
//! Callers address accounts with multibase VLAD strings. Internally the map is
//! indexed by [`VladHash`] = `SHA-256(canonical multibase VLAD)`, matching the
//! Keycard VLAD binding in [`crate::binding`].

use crate::api::SoftwareAccountsApi;
use crate::binding::{vlad_hash, VLAD_HASH_LEN};
use crate::encoding::{decode_vlad, encode_hex};
use crate::Error;
use multicid::Vlad;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Fixed-size cache key: SHA-256 of the canonical multibase VLAD string.
pub type VladHash = [u8; VLAD_HASH_LEN];

/// One cached account session (local software or Keycard-backed).
pub enum CachedAccount {
    /// In-memory software wallet + p-log.
    Local(SoftwareAccountsApi),
    /// Hardware Keycard session + p-log.
    #[cfg(feature = "pcsc")]
    Keycard(
        crate::api::AccountsApi<
            crate::KeycardWallet<nexum_apdu_transport_pcsc::PcscTransport>,
        >,
    ),
}

impl std::fmt::Debug for CachedAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CachedAccount::Local(_) => f.write_str("CachedAccount::Local"),
            #[cfg(feature = "pcsc")]
            CachedAccount::Keycard(_) => f.write_str("CachedAccount::Keycard"),
        }
    }
}

/// In-process multi-account cache keyed by [`VladHash`].
pub struct AccountCache {
    entries: Mutex<HashMap<VladHash, Arc<Mutex<CachedAccount>>>>,
}

impl Default for AccountCache {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AccountCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.entries.lock().map(|g| g.len()).unwrap_or(0);
        f.debug_struct("AccountCache")
            .field("len", &n)
            .finish()
    }
}

impl AccountCache {
    /// Empty cache.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Number of cached accounts.
    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .map(|g| g.len())
            .unwrap_or(0)
    }

    /// Whether the cache has no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Compute the cache key for a multibase VLAD string (decode → canonical encode → hash).
    pub fn key_from_multibase(vlad_multibase: &str) -> Result<VladHash, Error> {
        let vlad = decode_vlad(vlad_multibase)?;
        Ok(vlad_hash(&vlad))
    }

    /// Compute the cache key for a typed [`Vlad`].
    pub fn key_from_vlad(vlad: &Vlad) -> VladHash {
        vlad_hash(vlad)
    }

    /// Short hex prefix of a hash for error messages.
    pub fn hash_hex_short(key: &VladHash) -> String {
        let full = encode_hex(key);
        full.chars().take(16).collect()
    }

    /// Insert or replace an entry under the hash of `vlad_multibase`.
    pub fn insert(&self, vlad_multibase: &str, account: CachedAccount) -> Result<(), Error> {
        let key = Self::key_from_multibase(vlad_multibase)?;
        self.insert_by_hash(key, account);
        Ok(())
    }

    /// Insert or replace an entry under a precomputed hash.
    pub fn insert_by_hash(&self, key: VladHash, account: CachedAccount) {
        let mut guard = self.entries.lock().expect("account cache map lock");
        guard.insert(key, Arc::new(Mutex::new(account)));
    }

    /// Look up a cached account by multibase VLAD.
    pub fn get(&self, vlad_multibase: &str) -> Result<Arc<Mutex<CachedAccount>>, Error> {
        let key = Self::key_from_multibase(vlad_multibase)?;
        self.get_by_hash(&key)
    }

    /// Look up a cached account by hash.
    pub fn get_by_hash(&self, key: &VladHash) -> Result<Arc<Mutex<CachedAccount>>, Error> {
        let guard = self.entries.lock().expect("account cache map lock");
        guard.get(key).cloned().ok_or_else(|| {
            Error::AccountNotCached(Self::hash_hex_short(key))
        })
    }

    /// Whether a VLAD is present in the cache.
    pub fn contains(&self, vlad_multibase: &str) -> Result<bool, Error> {
        let key = Self::key_from_multibase(vlad_multibase)?;
        let guard = self.entries.lock().expect("account cache map lock");
        Ok(guard.contains_key(&key))
    }

    /// Remove one entry by multibase VLAD.
    pub fn remove(&self, vlad_multibase: &str) -> Result<(), Error> {
        let key = Self::key_from_multibase(vlad_multibase)?;
        let mut guard = self.entries.lock().expect("account cache map lock");
        if guard.remove(&key).is_none() {
            return Err(Error::AccountNotCached(Self::hash_hex_short(&key)));
        }
        Ok(())
    }

    /// Drop all cached accounts. Returns how many were removed.
    pub fn clear(&self) -> usize {
        let mut guard = self.entries.lock().expect("account cache map lock");
        let n = guard.len();
        guard.clear();
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::SoftwareAccountsApi;
    use crate::binding::vlad_hash_from_multibase;

    #[tokio::test]
    async fn insert_get_remove_clear() {
        let cache = AccountCache::new();
        assert!(cache.is_empty());

        let mut api = SoftwareAccountsApi::software();
        let summary = api.create_account().await.expect("create");
        let vlad = summary.vlad.clone();

        cache
            .insert(&vlad, CachedAccount::Local(api))
            .expect("insert");
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(&vlad).unwrap());

        let entry = cache.get(&vlad).expect("get");
        {
            let guard = entry.lock().unwrap();
            match &*guard {
                CachedAccount::Local(a) => {
                    assert_eq!(a.vlad().unwrap(), vlad);
                }
                #[cfg(feature = "pcsc")]
                CachedAccount::Keycard(_) => panic!("expected local"),
            }
        }

        cache.remove(&vlad).expect("remove");
        assert!(cache.is_empty());
        assert!(matches!(
            cache.get(&vlad),
            Err(Error::AccountNotCached(_))
        ));

        let mut api2 = SoftwareAccountsApi::software();
        let s2 = api2.create_account().await.unwrap();
        cache.insert(&s2.vlad, CachedAccount::Local(api2)).unwrap();
        assert_eq!(cache.clear(), 1);
        assert!(cache.is_empty());
    }

    #[test]
    fn key_is_32_bytes_and_stable() {
        // Use a well-formed path: hash helpers don't require a real VLAD for
        // vlad_hash_from_multibase, but key_from_multibase requires decode.
        // Stability of the binding hash function:
        let s = "zSampleVladMultibaseNotReal";
        let h1 = vlad_hash_from_multibase(s);
        let h2 = vlad_hash_from_multibase(s);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
        assert_ne!(h1, vlad_hash_from_multibase("other"));
    }

    #[tokio::test]
    async fn key_from_canonical_vlad_matches_insert() {
        let mut api = SoftwareAccountsApi::software();
        let summary = api.create_account().await.unwrap();
        let vlad = summary.vlad.clone();
        let key = AccountCache::key_from_multibase(&vlad).unwrap();
        assert_eq!(key.len(), 32);

        let cache = AccountCache::new();
        cache
            .insert_by_hash(key, CachedAccount::Local(api));
        assert!(cache.get(&vlad).is_ok());
        assert!(cache.get_by_hash(&key).is_ok());
    }

    #[test]
    fn missing_vlad_errors() {
        let cache = AccountCache::new();
        // Invalid multibase VLAD fails at decode, not cache miss.
        assert!(cache.get("not-a-vlad").is_err());
    }
}
