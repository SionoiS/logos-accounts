//! Domain API: verified p-log cache entries with external Multisig commits.
//!
//! Create uses software ephemerals (VLAD + `/entrykey`) and a peer-provided root
//! Multikey. All later mutations use prepare → external Multisig → commit.

use crate::config::{
    default_unlock_script, delegate_pubkey_key, delegated_branch_lock_script, key_under_branch,
    parse_branch_path, pubkey_key_path,
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

/// Serializable account ops for updates (maps to BetterSign `OpParams`).
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

fn ensure_ops_under_branch(ops: &[OpParams], branch: &Key) -> Result<(), Error> {
    if ops.is_empty() {
        return Err(Error::InvalidOp(
            "path update requires at least one operation".into(),
        ));
    }
    let pk_key = delegate_pubkey_key(branch)?;
    for op in ops {
        let key = op_key(op)?;
        if key == pk_key {
            return Err(Error::InvalidOp(format!(
                "cannot modify delegation key {pk_key} via path update; use revoke / delegate kinds"
            )));
        }
        if !key_under_branch(&key, branch) {
            return Err(Error::PathEscape(branch.to_string(), key.to_string()));
        }
    }
    Ok(())
}

fn op_key(op: &OpParams) -> Result<Key, Error> {
    match op {
        OpParams::Noop { key }
        | OpParams::Delete { key }
        | OpParams::UseStr { key, .. }
        | OpParams::UseBin { key, .. }
        | OpParams::UseKey { key, .. }
        | OpParams::UseCid { key, .. }
        | OpParams::KeyGen { key, .. }
        | OpParams::CidGen { key, .. } => Ok(key.clone()),
    }
}

fn new_challenge_id() -> String {
    use rand_core::{OsRng, RngCore};
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    encode_bytes_multibase(&buf)
}

/// How long a prepare/commit challenge remains valid.
const CHALLENGE_TTL: Duration = Duration::from_secs(15 * 60);

/// Kind of pending update (for events / client UX).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateKind {
    /// Root-signed ops (was update_account).
    Ops,
    /// Root-signed path delegation.
    Delegate,
    /// Root-signed path revoke.
    Revoke,
    /// Delegate-signed ops under a branch.
    PathOps,
}

/// Pending mutation awaiting an external Multisig.
#[derive(Debug)]
struct PendingUpdate {
    head_cid: String,
    unsigned: UnsignedUpdate,
    kind: UpdateKind,
    /// Branch path for path_ops / delegate / revoke (if any).
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

/// Request body for [`PlogAccount::prepare_update`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UpdateRequest {
    /// Root-signed ops (JSON array of AccountOp also accepted via `ops` field).
    Ops {
        /// Ops JSON array string or embedded ops — use `ops` as JSON value array.
        #[serde(default)]
        ops: Vec<AccountOp>,
    },
    /// Root-signed path delegation.
    Delegate {
        /// Branch path ending with `/`.
        path: String,
        /// Peer Multikey multibase.
        pubkey_multibase: String,
    },
    /// Root-signed revoke of a path delegation.
    Revoke {
        /// Branch path ending with `/`.
        path: String,
    },
    /// Delegate-signed ops under a branch.
    PathOps {
        /// Branch path ending with `/`.
        path: String,
        /// Ops under the branch.
        #[serde(default)]
        ops: Vec<AccountOp>,
    },
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

    /// Prepare an unsigned update for an external signer.
    pub fn prepare_update(&mut self, request_json: &str) -> Result<UpdateChallenge, Error> {
        self.purge_expired_challenges();
        let req: UpdateRequest =
            serde_json::from_str(request_json).map_err(|e| Error::Encoding(e.to_string()))?;

        let (kind, path, signing_key_path, spec) = match req {
            UpdateRequest::Ops { ops } => {
                let op_params: Vec<OpParams> = ops
                    .into_iter()
                    .map(AccountOp::into_op_params)
                    .collect::<Result<_, _>>()?;
                (
                    UpdateKind::Ops,
                    None,
                    pubkey_key_path().to_string(),
                    NextEntrySpec {
                        unlock: default_unlock_script(),
                        locks: None,
                        ops: op_params,
                    },
                )
            }
            UpdateRequest::Delegate {
                path,
                pubkey_multibase,
            } => {
                let branch = parse_branch_path(&path)?;
                let mk = decode_multikey(&pubkey_multibase)?;
                let pk_key = delegate_pubkey_key(&branch)?;
                let head = self.head_entry()?;
                let lock = delegated_branch_lock_script(branch.clone());
                let locks = locks_replacing_path(&head, &branch, Some(lock));
                let ops = vec![use_key_op(pk_key, mk)];
                (
                    UpdateKind::Delegate,
                    Some(branch.to_string()),
                    pubkey_key_path().to_string(),
                    NextEntrySpec {
                        unlock: default_unlock_script(),
                        locks: Some(locks),
                        ops,
                    },
                )
            }
            UpdateRequest::Revoke { path } => {
                let branch = parse_branch_path(&path)?;
                let pk_key = delegate_pubkey_key(&branch)?;
                let head = self.head_entry()?;
                let locks = locks_replacing_path(&head, &branch, None);
                let ops = vec![OpParams::Delete { key: pk_key }];
                (
                    UpdateKind::Revoke,
                    Some(branch.to_string()),
                    pubkey_key_path().to_string(),
                    NextEntrySpec {
                        unlock: default_unlock_script(),
                        locks: Some(locks),
                        ops,
                    },
                )
            }
            UpdateRequest::PathOps { path, ops } => {
                let branch = parse_branch_path(&path)?;
                self.ensure_path_delegated(&branch)?;
                let op_params: Vec<OpParams> = ops
                    .into_iter()
                    .map(AccountOp::into_op_params)
                    .collect::<Result<_, _>>()?;
                ensure_ops_under_branch(&op_params, &branch)?;
                let signing_key = delegate_pubkey_key(&branch)?;
                (
                    UpdateKind::PathOps,
                    Some(branch.to_string()),
                    signing_key.to_string(),
                    NextEntrySpec {
                        unlock: default_unlock_script(),
                        locks: None,
                        ops: op_params,
                    },
                )
            }
        };

        let vlad = self.vlad();
        let head_cid = self.current_head_cid();
        let unsigned = prepare_next_entry(&self.log, spec)?;
        let challenge_id = new_challenge_id();
        let message_multibase = encode_bytes_multibase(&unsigned.message);

        self.pending.insert(
            challenge_id.clone(),
            PendingUpdate {
                head_cid: head_cid.clone(),
                unsigned,
                kind: kind.clone(),
                path: path.clone(),
                created_at: Instant::now(),
            },
        );

        Ok(UpdateChallenge {
            challenge_id,
            vlad,
            kind,
            path,
            signing_key_path,
            head_cid,
            message_multibase,
            message_encoding: "entry-bytes".into(),
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

    fn head_entry(&self) -> Result<Entry, Error> {
        let (_, last, _) = self
            .log
            .verify()
            .last()
            .ok_or_else(|| Error::PlogVerifyFailed("empty provenance log".into()))??;
        Ok(last)
    }

    fn ensure_path_delegated(&self, branch: &Key) -> Result<(), Error> {
        let delegations = self.list_delegations()?;
        let path = branch.to_string();
        if delegations.iter().any(|d| d.path == path) {
            Ok(())
        } else {
            Err(Error::PathNotDelegated(path))
        }
    }
}

/// Parse `request_json` for prepare_update (also accepts ops as JSON array via wrapper).
pub fn parse_update_request_json(s: &str) -> Result<UpdateRequest, Error> {
    serde_json::from_str(s).map_err(|e| Error::Encoding(format!("request_json: {e}")))
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
        assert_eq!(acct2.get_value("/pubkey").unwrap(), acct.get_value("/pubkey").unwrap());
    }

    #[tokio::test]
    async fn prepare_commit_ops_with_external_root() {
        let (sk, pk) = gen_keypair();
        let (mut acct, _) = PlogAccount::create(&encode_multikey(&pk))
            .await
            .unwrap();

        let req = r#"{"kind":"ops","ops":[{"op":"use_str","key":"/profile/name","value":"alice"}]}"#;
        let challenge = acct.prepare_update(req).unwrap();
        assert_eq!(challenge.signing_key_path, "/pubkey");
        assert_eq!(challenge.kind, UpdateKind::Ops);

        let sig = sign_message(&sk, &challenge.message_multibase);
        let (summary, kind, _) = acct
            .commit_update(&challenge.challenge_id, &sig)
            .unwrap();
        assert_eq!(kind, UpdateKind::Ops);
        assert_eq!(
            acct.get_value("/profile/name").unwrap(),
            PlogPathValue::Str("alice".into())
        );
        assert_eq!(summary.vlad, acct.vlad());
    }

    #[tokio::test]
    async fn delegate_and_path_ops_external() {
        let (root_sk, root_pk) = gen_keypair();
        let (del_sk, del_pk) = gen_keypair();
        let (mut acct, _) = PlogAccount::create(&encode_multikey(&root_pk))
            .await
            .unwrap();

        let del_req = serde_json::json!({
            "kind": "delegate",
            "path": "/apps/chat/",
            "pubkey_multibase": encode_multikey(&del_pk),
        })
        .to_string();
        let ch = acct.prepare_update(&del_req).unwrap();
        let sig = sign_message(&root_sk, &ch.message_multibase);
        let (_, kind, path) = acct.commit_update(&ch.challenge_id, &sig).unwrap();
        assert_eq!(kind, UpdateKind::Delegate);
        assert_eq!(path.as_deref(), Some("/apps/chat/"));

        let dels = acct.list_delegations().unwrap();
        assert_eq!(dels.len(), 1);
        assert_eq!(dels[0].path, "/apps/chat/");

        let path_req = serde_json::json!({
            "kind": "path_ops",
            "path": "/apps/chat/",
            "ops": [{"op":"use_str","key":"/apps/chat/room","value":"lobby"}],
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
    async fn head_mismatch_and_bad_sig() {
        let (sk, pk) = gen_keypair();
        let (mut acct, _) = PlogAccount::create(&encode_multikey(&pk))
            .await
            .unwrap();

        let ch1 = acct
            .prepare_update(r#"{"kind":"ops","ops":[]}"#)
            .unwrap();
        // Move head with another update first
        let ch2 = acct
            .prepare_update(r#"{"kind":"ops","ops":[{"op":"use_str","key":"/x","value":"1"}]}"#)
            .unwrap();
        let sig2 = sign_message(&sk, &ch2.message_multibase);
        acct.commit_update(&ch2.challenge_id, &sig2).unwrap();

        // ch1 should be gone (cleared on commit) or head mismatch
        let sig1 = sign_message(&sk, &ch1.message_multibase);
        let err = acct.commit_update(&ch1.challenge_id, &sig1).unwrap_err();
        assert!(matches!(
            err,
            Error::ChallengeNotFound(_) | Error::HeadMismatch(_, _)
        ));
    }

    #[tokio::test]
    async fn path_ops_escape_rejected() {
        let (root_sk, root_pk) = gen_keypair();
        let (_del_sk, del_pk) = gen_keypair();
        let (mut acct, _) = PlogAccount::create(&encode_multikey(&root_pk))
            .await
            .unwrap();
        let del_req = serde_json::json!({
            "kind": "delegate",
            "path": "/apps/chat/",
            "pubkey_multibase": encode_multikey(&del_pk),
        })
        .to_string();
        let ch = acct.prepare_update(&del_req).unwrap();
        acct.commit_update(&ch.challenge_id, &sign_message(&root_sk, &ch.message_multibase))
            .unwrap();

        let bad = serde_json::json!({
            "kind": "path_ops",
            "path": "/apps/chat/",
            "ops": [{"op":"use_str","key":"/other","value":"x"}],
        })
        .to_string();
        assert!(matches!(
            acct.prepare_update(&bad),
            Err(Error::PathEscape(_, _))
        ));
    }
}
