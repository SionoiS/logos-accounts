//! Domain API: verified p-log cache entries with external Multisig commits.
//!
//! Create uses software ephemerals (VLAD + `/entrykey`) and a peer-provided root
//! Multikey. All later mutations use prepare → external Multisig → commit.
//!
//! # Prepare surfaces
//!
//! - [`PlogAccount::prepare_update`] — raw next entry: lock scripts + p-log ops
//! - [`PlogAccount::prepare_delegate`] / [`PlogAccount::prepare_revoke`] — sugar
//!   over lock + KV mutations with closest-parent (or root) signing

use crate::config::{
    default_unlock_script, delegate_pubkey_key, delegated_branch_lock_script, parse_branch_path,
    pubkey_key_path,
};
use crate::encoding::{
    decode_bytes_multibase, decode_multikey, decode_multisig, decode_plog, encode_bytes_multibase,
    encode_cid, encode_multikey, encode_plog, encode_vlad, plog_from_bytes, plog_to_bytes,
};
use crate::entry_update::{
    commit_with_multisig, locks_replacing_path, prepare_next_entry, use_key_op, NextEntrySpec,
    UnsignedUpdate,
};
use crate::ephemeral_open::open_plog_with_external_pubkey;
use crate::Error;
use bs::ops::update::OpParams;
use multikey::Multikey;
use provenance_log::entry::Entry;
use provenance_log::{Key, Log, Script, Value};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum PlogPathValue {
    /// UTF-8 string stored via update/str (or equivalent).
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

/// P-log value payload for an `update` op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlogValue {
    /// UTF-8 string.
    Str(String),
    /// Multibase-encoded binary (or Multikey) payload.
    Data(String),
}

/// Raw p-log mutation op (`noop` / `delete` / `update`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum PlogOp {
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
    /// Create or replace a value at a key path.
    Update {
        /// Logical key path.
        key: String,
        /// Value to store.
        value: PlogValue,
    },
}

impl PlogOp {
    /// Convert to BetterSign [`OpParams`].
    pub fn into_op_params(self) -> Result<OpParams, Error> {
        match self {
            PlogOp::Noop { key } => Ok(OpParams::Noop {
                key: parse_key(&key)?,
            }),
            PlogOp::Delete { key } => Ok(OpParams::Delete {
                key: parse_key(&key)?,
            }),
            PlogOp::Update { key, value } => {
                let key = parse_key(&key)?;
                match value {
                    PlogValue::Str(s) => Ok(OpParams::UseStr { key, s }),
                    PlogValue::Data(data_multibase) => Ok(OpParams::UseBin {
                        key,
                        data: decode_bytes_multibase(&data_multibase)?,
                    }),
                }
            }
        }
    }
}

/// One lock script bound to a path (Comrade source).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockScriptJson {
    /// Lock path (e.g. `/` or `/apps/chat/`).
    pub path: String,
    /// Comrade lock source code.
    pub code: String,
}

/// How to build the next entry's lock set from the head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LockSpec {
    /// `"inherit"` — copy head locks unchanged.
    Keyword(String),
    /// Full replacement lock list.
    Replace {
        /// Scripts for the next entry.
        replace: Vec<LockScriptJson>,
    },
    /// Replace or append a single path's lock.
    Upsert {
        /// Lock to upsert by path.
        upsert: LockScriptJson,
    },
    /// Drop the lock at this path (keep others).
    Remove {
        /// Branch or path whose lock is removed.
        remove: String,
    },
}

impl Default for LockSpec {
    fn default() -> Self {
        Self::Keyword("inherit".into())
    }
}

/// Request body for [`PlogAccount::prepare_update`] (raw entry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryUpdateRequest {
    /// Next-entry locks; default inherit.
    #[serde(default)]
    pub locks: LockSpec,
    /// Mutation ops.
    #[serde(default)]
    pub ops: Vec<PlogOp>,
    /// Multikey path the peer will sign as (default `/pubkey`).
    #[serde(default)]
    pub sign_as: Option<String>,
}

/// Kind of pending update (for events / client UX).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateKind {
    /// Raw entry prepare (`prepare_update`).
    Entry,
    /// Path delegation sugar.
    Delegate,
    /// Path revoke sugar.
    Revoke,
}

/// Internal prepare assembly input (after sugar expansion).
#[derive(Debug, Clone)]
struct PrepareEntrySpec {
    locks: LockSpec,
    ops: Vec<OpParams>,
    sign_as: String,
    kind: UpdateKind,
    path: Option<String>,
}

/// Pending mutation awaiting an external Multisig.
#[derive(Debug)]
struct PendingUpdate {
    head_cid: String,
    unsigned: UnsignedUpdate,
    kind: UpdateKind,
    /// Branch path for delegate / revoke (if any).
    path: Option<String>,
    created_at: Instant,
}

/// One delegated branch as seen at the verified head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathDelegation {
    /// Branch path (trailing `/`), e.g. `/apps/chat/`.
    pub path: String,
    /// Multibase Multikey at `{path}pubkey`.
    pub pubkey: String,
}

/// Opaque prepare response for external signers (LIDL JSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateChallenge {
    /// Opaque id for [`PlogAccount::commit_update`].
    pub challenge_id: String,
    /// Account VLAD (multibase).
    pub vlad: String,
    /// Update kind.
    pub kind: UpdateKind,
    /// Branch path when relevant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Logical key path the peer must sign as.
    pub signing_key_path: String,
    /// Head CID at prepare time (commit fails if head moved).
    pub head_cid: String,
    /// Message to sign (unsigned entry bytes, multibase).
    pub message_multibase: String,
    /// Encoding of `message_multibase` (`entry-bytes`).
    pub message_encoding: String,
}

fn parse_key(s: &str) -> Result<Key, Error> {
    Key::try_from(s).map_err(|e| Error::InvalidOp(format!("invalid key path {s}: {e}")))
}

fn new_challenge_id() -> String {
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    encode_bytes_multibase(&buf)
}

/// How long a prepare/commit challenge remains valid.
const CHALLENGE_TTL: Duration = Duration::from_secs(15 * 60);

fn plog_ops_to_params(ops: Vec<PlogOp>) -> Result<Vec<OpParams>, Error> {
    ops.into_iter().map(PlogOp::into_op_params).collect()
}

fn lock_script_from_json(s: &LockScriptJson) -> Result<Script, Error> {
    let path = parse_key(&s.path)?;
    Ok(Script::Code(path, s.code.clone()))
}

fn lock_spec_to_scripts(head: &Entry, spec: &LockSpec) -> Result<Option<Vec<Script>>, Error> {
    match spec {
        LockSpec::Keyword(k) => {
            if k == "inherit" {
                Ok(None)
            } else {
                Err(Error::InvalidOp(format!(
                    "unknown locks keyword {k:?}; use \"inherit\" or an object"
                )))
            }
        }
        LockSpec::Replace { replace } => {
            let scripts = replace
                .iter()
                .map(lock_script_from_json)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Some(scripts))
        }
        LockSpec::Upsert { upsert } => {
            let path = parse_key(&upsert.path)?;
            let script = lock_script_from_json(upsert)?;
            Ok(Some(locks_replacing_path(head, &path, Some(script))))
        }
        LockSpec::Remove { remove } => {
            let path = parse_key(remove)?;
            Ok(Some(locks_replacing_path(head, &path, None)))
        }
    }
}

/// Longest proper-ancestor delegated branch's `{branch}pubkey`, else `/pubkey`.
pub fn resolve_closest_parent_signing_key(
    target: &Key,
    delegations: &[PathDelegation],
) -> Result<String, Error> {
    let mut best: Option<Key> = None;
    for d in delegations {
        let d_key = match parse_branch_path(&d.path) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if d_key == *target {
            continue;
        }
        if d_key.parent_of(target) {
            let take = match &best {
                None => true,
                Some(b) => d_key.as_str().len() > b.as_str().len(),
            };
            if take {
                best = Some(d_key);
            }
        }
    }
    match best {
        Some(branch) => Ok(delegate_pubkey_key(&branch)?.to_string()),
        None => Ok(pubkey_key_path().to_string()),
    }
}

/// Parse raw `prepare_update` JSON.
pub fn parse_entry_update_request(s: &str) -> Result<EntryUpdateRequest, Error> {
    serde_json::from_str(s).map_err(|e| Error::Encoding(format!("request_json: {e}")))
}

/// Parse JSON array of [`PlogOp`]s.
pub fn parse_ops_json(ops_json: &str) -> Result<Vec<OpParams>, Error> {
    if ops_json.trim().is_empty() || ops_json.trim() == "[]" {
        return Ok(Vec::new());
    }
    let ops: Vec<PlogOp> =
        serde_json::from_str(ops_json).map_err(|e| Error::Encoding(e.to_string()))?;
    plog_ops_to_params(ops)
}

/// One cached account: verified p-log + prepare/commit challenges (no private keys).
#[derive(Debug)]
pub struct PlogAccount {
    log: Log,
    pending: HashMap<String, PendingUpdate>,
}

impl PlogAccount {
    /// One-shot create: ephemeral VLAD + `/entrykey`, external root Multikey, insert-ready account.
    pub async fn create(pubkey_multibase: &str) -> Result<(Self, AccountSummary), Error> {
        let mk = decode_multikey(pubkey_multibase)?;
        let log = open_plog_with_external_pubkey(mk).await?;
        let summary = summary_from_verified_plog(&log)?;
        Ok((
            Self {
                log,
                pending: HashMap::new(),
            },
            summary,
        ))
    }

    /// Import a fully signed p-log (full-chain verify required).
    pub fn import(plog_multibase: &str) -> Result<(Self, AccountSummary), Error> {
        let log = decode_plog(plog_multibase)?;
        let summary = summary_from_verified_plog(&log)?;
        Ok((
            Self {
                log,
                pending: HashMap::new(),
            },
            summary,
        ))
    }

    /// Import from raw plog bytes.
    pub fn import_bytes(plog_bytes: &[u8]) -> Result<(Self, AccountSummary), Error> {
        let log = plog_from_bytes(plog_bytes)?;
        let summary = summary_from_verified_plog(&log)?;
        Ok((
            Self {
                log,
                pending: HashMap::new(),
            },
            summary,
        ))
    }

    /// Account summary from the current verified log.
    pub fn summary(&self) -> Result<AccountSummary, Error> {
        summary_from_verified_plog(&self.log)
    }

    /// Multibase VLAD.
    pub fn vlad(&self) -> String {
        encode_vlad(&self.log.vlad)
    }

    /// Export plog as multibase.
    pub fn export_plog(&self) -> String {
        encode_plog(&self.log)
    }

    /// Export plog as raw bytes.
    pub fn export_plog_bytes(&self) -> Vec<u8> {
        plog_to_bytes(&self.log)
    }

    /// Read a logical key path from the verified head KVP.
    pub fn get_value(&self, path: &str) -> Result<PlogPathValue, Error> {
        get_plog_value(&self.log, path)
    }

    /// List active path delegations at the verified head.
    pub fn list_delegations(&self) -> Result<Vec<PathDelegation>, Error> {
        let mut last_entry: Option<Entry> = None;
        let mut last_kvp_keys: Vec<(Key, Value)> = Vec::new();
        let mut any = false;
        for item in self.log.verify() {
            any = true;
            match item {
                Ok((_n, entry, kvp)) => {
                    last_entry = Some(entry);
                    last_kvp_keys = kvp.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                }
                Err(e) => return Err(Error::PlogVerifyFailed(e.to_string())),
            }
        }
        if !any {
            return Err(Error::PlogVerifyFailed("empty provenance log".into()));
        }
        let entry = last_entry.expect("any implies entry");

        let mut out = Vec::new();
        for lock in entry.locks() {
            let path = lock.path();
            if !path.is_branch() || path.as_str() == "/" {
                continue;
            }
            let is_delegated = match lock {
                Script::Code(p, code) => {
                    let expected = format!(r#"check_signature("{}pubkey""#, p.as_str());
                    code.contains(&expected) || code.contains("branch(\"pubkey\")")
                }
                _ => false,
            };
            if !is_delegated {
                continue;
            }
            let pk_key = match delegate_pubkey_key(&path) {
                Ok(k) => k,
                Err(_) => continue,
            };
            let pubkey = last_kvp_keys.iter().find_map(|(k, v)| {
                if k != &pk_key {
                    return None;
                }
                match v {
                    Value::Data(b) => Multikey::try_from(b.as_slice())
                        .ok()
                        .map(|mk| encode_multikey(&mk)),
                    Value::Str(s) => Some(s.clone()),
                    Value::Nil => None,
                }
            });
            if let Some(pubkey) = pubkey {
                out.push(PathDelegation {
                    path: path.to_string(),
                    pubkey,
                });
            }
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    fn current_head_cid(&self) -> String {
        encode_cid(&self.log.head)
    }

    fn purge_expired_challenges(&mut self) {
        let now = Instant::now();
        self.pending
            .retain(|_, p| now.duration_since(p.created_at) < CHALLENGE_TTL);
    }

    fn head_entry(&self) -> Result<Entry, Error> {
        let (_, last, _) = self
            .log
            .verify()
            .last()
            .ok_or_else(|| Error::PlogVerifyFailed("empty provenance log".into()))??;
        Ok(last)
    }

    /// Core prepare: assemble unsigned entry and store a challenge.
    fn prepare_entry(&mut self, spec: PrepareEntrySpec) -> Result<UpdateChallenge, Error> {
        self.purge_expired_challenges();
        let head = self.head_entry()?;
        let locks = lock_spec_to_scripts(&head, &spec.locks)?;
        let next = NextEntrySpec {
            unlock: default_unlock_script(),
            locks,
            ops: spec.ops,
        };

        let vlad = self.vlad();
        let head_cid = self.current_head_cid();
        let unsigned = prepare_next_entry(&self.log, next)?;
        let challenge_id = new_challenge_id();
        let message_multibase = encode_bytes_multibase(&unsigned.message);

        self.pending.insert(
            challenge_id.clone(),
            PendingUpdate {
                head_cid: head_cid.clone(),
                unsigned,
                kind: spec.kind.clone(),
                path: spec.path.clone(),
                created_at: Instant::now(),
            },
        );

        Ok(UpdateChallenge {
            challenge_id,
            vlad,
            kind: spec.kind,
            path: spec.path,
            signing_key_path: spec.sign_as,
            head_cid,
            message_multibase,
            message_encoding: "entry-bytes".into(),
        })
    }

    /// Prepare a raw entry (locks + ops) for an external Multisig.
    pub fn prepare_update(&mut self, request_json: &str) -> Result<UpdateChallenge, Error> {
        let req = parse_entry_update_request(request_json)?;
        let sign_as = req
            .sign_as
            .unwrap_or_else(|| pubkey_key_path().to_string());
        // Validate sign_as is a key path
        let _ = parse_key(&sign_as)?;
        self.prepare_entry(PrepareEntrySpec {
            locks: req.locks,
            ops: plog_ops_to_params(req.ops)?,
            sign_as,
            kind: UpdateKind::Entry,
            path: None,
        })
    }

    /// Sugar: delegate `path` to `pubkey_multibase` (lock upsert + pubkey update).
    ///
    /// Signing key is the closest proper-ancestor delegated branch, else `/pubkey`.
    pub fn prepare_delegate(
        &mut self,
        path: &str,
        pubkey_multibase: &str,
    ) -> Result<UpdateChallenge, Error> {
        let branch = parse_branch_path(path)?;
        let mk = decode_multikey(pubkey_multibase)?;
        let pk_key = delegate_pubkey_key(&branch)?;
        let lock = delegated_branch_lock_script(branch.clone());
        let (lock_path, lock_code) = match lock {
            Script::Code(p, c) => (p.to_string(), c),
            other => {
                return Err(Error::InvalidOp(format!(
                    "expected Code lock script, got {other:?}"
                )));
            }
        };
        let sign_as =
            resolve_closest_parent_signing_key(&branch, &self.list_delegations()?)?;
        self.prepare_entry(PrepareEntrySpec {
            locks: LockSpec::Upsert {
                upsert: LockScriptJson {
                    path: lock_path,
                    code: lock_code,
                },
            },
            ops: vec![use_key_op(pk_key, mk)],
            sign_as,
            kind: UpdateKind::Delegate,
            path: Some(branch.to_string()),
        })
    }

    /// Sugar: revoke delegation at `path` (lock remove + pubkey delete).
    ///
    /// Signing key is the closest proper-ancestor delegated branch, else `/pubkey`.
    pub fn prepare_revoke(&mut self, path: &str) -> Result<UpdateChallenge, Error> {
        let branch = parse_branch_path(path)?;
        let pk_key = delegate_pubkey_key(&branch)?;
        let sign_as =
            resolve_closest_parent_signing_key(&branch, &self.list_delegations()?)?;
        self.prepare_entry(PrepareEntrySpec {
            locks: LockSpec::Remove {
                remove: branch.to_string(),
            },
            ops: vec![OpParams::Delete { key: pk_key }],
            sign_as,
            kind: UpdateKind::Revoke,
            path: Some(branch.to_string()),
        })
    }

    /// Commit a prepared update with an external Multisig.
    ///
    /// Returns the new summary and the kind (for event emission).
    pub fn commit_update(
        &mut self,
        challenge_id: &str,
        signature_multibase: &str,
    ) -> Result<(AccountSummary, UpdateKind, Option<String>), Error> {
        self.purge_expired_challenges();
        let pending = self
            .pending
            .remove(challenge_id)
            .ok_or_else(|| Error::ChallengeNotFound(challenge_id.to_string()))?;

        let current_head = self.current_head_cid();
        if current_head != pending.head_cid {
            return Err(Error::HeadMismatch(pending.head_cid, current_head));
        }

        let signature = decode_multisig(signature_multibase)?;
        commit_with_multisig(&mut self.log, pending.unsigned.entry, signature)?;
        let kind = pending.kind;
        let path = pending.path;
        self.pending.clear();
        let summary = summary_from_verified_plog(&self.log)?;
        Ok((summary, kind, path))
    }

    /// Drop a pending prepare challenge without committing.
    pub fn cancel_update(&mut self, challenge_id: &str) -> Result<(), Error> {
        self.purge_expired_challenges();
        if self.pending.remove(challenge_id).is_none() {
            return Err(Error::ChallengeNotFound(challenge_id.to_string()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{decode_bytes_multibase, encode_multisig};
    use multicodec::Codec;
    use multikey::{Builder, Views};
    use rand_core::OsRng;

    fn gen_keypair() -> (Multikey, Multikey) {
        let mut rng = OsRng;
        let sk = Builder::new_from_random_bytes(Codec::Secp256K1Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();
        (sk, pk)
    }

    fn sign_message(sk: &Multikey, message_multibase: &str) -> String {
        let msg = decode_bytes_multibase(message_multibase).unwrap();
        let sig = sk.sign_view().unwrap().sign(&msg, false, None).unwrap();
        encode_multisig(&sig)
    }

    #[tokio::test]
    async fn create_import_export_roundtrip() {
        let (_sk, pk) = gen_keypair();
        let pk_mb = encode_multikey(&pk);
        let (acct, summary) = PlogAccount::create(&pk_mb).await.expect("create");
        assert!(!summary.vlad.is_empty());
        assert!(summary.pubkey.is_some());

        let exported = acct.export_plog();
        let (acct2, s2) = PlogAccount::import(&exported).expect("import");
        assert_eq!(s2.vlad, summary.vlad);
        assert_eq!(
            acct2.get_value("/pubkey").unwrap(),
            acct.get_value("/pubkey").unwrap()
        );
    }

    #[tokio::test]
    async fn prepare_commit_entry_with_external_root() {
        let (sk, pk) = gen_keypair();
        let (mut acct, _) = PlogAccount::create(&encode_multikey(&pk))
            .await
            .unwrap();

        let req = r#"{"ops":[{"op":"update","key":"/profile/name","value":{"str":"alice"}}]}"#;
        let challenge = acct.prepare_update(req).unwrap();
        assert_eq!(challenge.signing_key_path, "/pubkey");
        assert_eq!(challenge.kind, UpdateKind::Entry);

        let sig = sign_message(&sk, &challenge.message_multibase);
        let (summary, kind, _) = acct
            .commit_update(&challenge.challenge_id, &sig)
            .unwrap();
        assert_eq!(kind, UpdateKind::Entry);
        assert_eq!(
            acct.get_value("/profile/name").unwrap(),
            PlogPathValue::Str("alice".into())
        );
        assert_eq!(summary.vlad, acct.vlad());
    }

    #[tokio::test]
    async fn prepare_delegate_root_and_path_kv() {
        let (root_sk, root_pk) = gen_keypair();
        let (del_sk, del_pk) = gen_keypair();
        let (mut acct, _) = PlogAccount::create(&encode_multikey(&root_pk))
            .await
            .unwrap();

        let ch = acct
            .prepare_delegate("/apps/chat/", &encode_multikey(&del_pk))
            .unwrap();
        assert_eq!(ch.signing_key_path, "/pubkey");
        assert_eq!(ch.kind, UpdateKind::Delegate);
        let sig = sign_message(&root_sk, &ch.message_multibase);
        let (_, kind, path) = acct.commit_update(&ch.challenge_id, &sig).unwrap();
        assert_eq!(kind, UpdateKind::Delegate);
        assert_eq!(path.as_deref(), Some("/apps/chat/"));

        let dels = acct.list_delegations().unwrap();
        assert_eq!(dels.len(), 1);
        assert_eq!(dels[0].path, "/apps/chat/");

        // Branch-scoped KV via raw entry + sign_as
        let path_req = serde_json::json!({
            "ops": [{"op":"update","key":"/apps/chat/room","value":{"str":"lobby"}}],
            "sign_as": "/apps/chat/pubkey",
        })
        .to_string();
        let ch2 = acct.prepare_update(&path_req).unwrap();
        assert_eq!(ch2.signing_key_path, "/apps/chat/pubkey");
        let sig2 = sign_message(&del_sk, &ch2.message_multibase);
        acct.commit_update(&ch2.challenge_id, &sig2).unwrap();
        assert_eq!(
            acct.get_value("/apps/chat/room").unwrap(),
            PlogPathValue::Str("lobby".into())
        );
    }

    #[tokio::test]
    async fn raw_entry_delegate_matches_sugar() {
        let (root_sk, root_pk) = gen_keypair();
        let (_del_sk, del_pk) = gen_keypair();
        let (mut acct, _) = PlogAccount::create(&encode_multikey(&root_pk))
            .await
            .unwrap();

        let mk_bytes: Vec<u8> = del_pk.clone().into();
        let branch = parse_branch_path("/apps/chat/").unwrap();
        let lock = delegated_branch_lock_script(branch.clone());
        let (lock_path, lock_code) = match lock {
            Script::Code(p, c) => (p.to_string(), c),
            _ => panic!("code lock"),
        };
        let raw = serde_json::json!({
            "locks": {
                "upsert": { "path": lock_path, "code": lock_code }
            },
            "ops": [{
                "op": "update",
                "key": "/apps/chat/pubkey",
                "value": { "data": encode_bytes_multibase(&mk_bytes) }
            }]
        })
        .to_string();
        let ch = acct.prepare_update(&raw).unwrap();
        acct.commit_update(&ch.challenge_id, &sign_message(&root_sk, &ch.message_multibase))
            .unwrap();
        let dels = acct.list_delegations().unwrap();
        assert_eq!(dels.len(), 1);
        assert_eq!(dels[0].path, "/apps/chat/");
    }

    #[tokio::test]
    async fn nested_delegate_uses_closest_parent_signer() {
        let (root_sk, root_pk) = gen_keypair();
        let (apps_sk, apps_pk) = gen_keypair();
        let (_chat_sk, chat_pk) = gen_keypair();
        let (mut acct, _) = PlogAccount::create(&encode_multikey(&root_pk))
            .await
            .unwrap();

        let ch = acct
            .prepare_delegate("/apps/", &encode_multikey(&apps_pk))
            .unwrap();
        assert_eq!(ch.signing_key_path, "/pubkey");
        acct.commit_update(&ch.challenge_id, &sign_message(&root_sk, &ch.message_multibase))
            .unwrap();

        let ch2 = acct
            .prepare_delegate("/apps/chat/", &encode_multikey(&chat_pk))
            .unwrap();
        assert_eq!(ch2.signing_key_path, "/apps/pubkey");
        acct.commit_update(
            &ch2.challenge_id,
            &sign_message(&apps_sk, &ch2.message_multibase),
        )
        .unwrap();

        let dels = acct.list_delegations().unwrap();
        assert!(dels.iter().any(|d| d.path == "/apps/"));
        assert!(dels.iter().any(|d| d.path == "/apps/chat/"));

        // Sibling path falls back to root
        let (_other_sk, other_pk) = gen_keypair();
        let ch3 = acct
            .prepare_delegate("/other/", &encode_multikey(&other_pk))
            .unwrap();
        assert_eq!(ch3.signing_key_path, "/pubkey");
        acct.cancel_update(&ch3.challenge_id).unwrap();
    }

    #[tokio::test]
    async fn revoke_uses_closest_parent_and_clears_grant() {
        let (root_sk, root_pk) = gen_keypair();
        let (apps_sk, apps_pk) = gen_keypair();
        let (_chat_sk, chat_pk) = gen_keypair();
        let (mut acct, _) = PlogAccount::create(&encode_multikey(&root_pk))
            .await
            .unwrap();

        let ch = acct
            .prepare_delegate("/apps/", &encode_multikey(&apps_pk))
            .unwrap();
        acct.commit_update(&ch.challenge_id, &sign_message(&root_sk, &ch.message_multibase))
            .unwrap();
        let ch2 = acct
            .prepare_delegate("/apps/chat/", &encode_multikey(&chat_pk))
            .unwrap();
        acct.commit_update(
            &ch2.challenge_id,
            &sign_message(&apps_sk, &ch2.message_multibase),
        )
        .unwrap();

        let rev = acct.prepare_revoke("/apps/chat/").unwrap();
        assert_eq!(rev.signing_key_path, "/apps/pubkey");
        assert_eq!(rev.kind, UpdateKind::Revoke);
        acct.commit_update(
            &rev.challenge_id,
            &sign_message(&apps_sk, &rev.message_multibase),
        )
        .unwrap();

        let dels = acct.list_delegations().unwrap();
        assert!(dels.iter().all(|d| d.path != "/apps/chat/"));
        assert!(dels.iter().any(|d| d.path == "/apps/"));
        assert!(matches!(
            acct.get_value("/apps/chat/pubkey"),
            Err(Error::PathNotFound(_))
        ));
    }

    #[tokio::test]
    async fn head_mismatch_and_bad_sig() {
        let (sk, pk) = gen_keypair();
        let (mut acct, _) = PlogAccount::create(&encode_multikey(&pk))
            .await
            .unwrap();

        let ch1 = acct.prepare_update(r#"{"ops":[]}"#).unwrap();
        let ch2 = acct
            .prepare_update(
                r#"{"ops":[{"op":"update","key":"/x","value":{"str":"1"}}]}"#,
            )
            .unwrap();
        let sig2 = sign_message(&sk, &ch2.message_multibase);
        acct.commit_update(&ch2.challenge_id, &sig2).unwrap();

        let sig1 = sign_message(&sk, &ch1.message_multibase);
        let err = acct.commit_update(&ch1.challenge_id, &sig1).unwrap_err();
        assert!(matches!(
            err,
            Error::ChallengeNotFound(_) | Error::HeadMismatch(_, _)
        ));
    }

    #[test]
    fn closest_parent_resolver_unit() {
        let target = parse_branch_path("/apps/chat/rooms/").unwrap();
        let dels = vec![
            PathDelegation {
                path: "/apps/".into(),
                pubkey: "a".into(),
            },
            PathDelegation {
                path: "/apps/chat/".into(),
                pubkey: "b".into(),
            },
        ];
        assert_eq!(
            resolve_closest_parent_signing_key(&target, &dels).unwrap(),
            "/apps/chat/pubkey"
        );
        assert_eq!(
            resolve_closest_parent_signing_key(
                &parse_branch_path("/other/").unwrap(),
                &dels
            )
            .unwrap(),
            "/pubkey"
        );
        // Proper parent only: exact match on target is ignored
        assert_eq!(
            resolve_closest_parent_signing_key(
                &parse_branch_path("/apps/chat/").unwrap(),
                &dels
            )
            .unwrap(),
            "/apps/pubkey"
        );
    }
}
