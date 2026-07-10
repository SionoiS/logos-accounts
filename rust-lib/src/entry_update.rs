//! Low-level p-log entry construction for external Multisig commits.
//!
//! Mirrors BetterSign `update_plog` assembly so prepare/commit can attach a proof
//! without an in-process wallet, and so revoke can replace (not only append)
//! entry lock scripts.

use crate::config::default_unlock_script;
use crate::Error;
use bs::ops::update::op;
use bs::ops::update::OpParams;
use multicid::Cid;
use multikey::Multikey;
use multisig::Multisig;
use provenance_log::entry::{Entry, ENTRY_VERSION};
use provenance_log::{Key, Lipmaa as _, Log, OpId, Script};

/// A fully assembled unsigned entry ready for signing, plus the bytes to sign.
#[derive(Clone, Debug)]
pub struct UnsignedUpdate {
    /// Entry with empty proof.
    pub entry: Entry,
    /// Canonical serialized form that Multikey signers sign over.
    pub message: Vec<u8>,
}

/// Options for building the next log entry from the current head.
#[derive(Clone, Debug)]
pub struct NextEntrySpec {
    /// Unlock script for the new entry.
    pub unlock: Script,
    /// Complete lock set for the *next* entry (not delta). `None` = inherit head locks as-is.
    pub locks: Option<Vec<Script>>,
    /// Mutation ops for this entry.
    pub ops: Vec<OpParams>,
}

impl Default for NextEntrySpec {
    fn default() -> Self {
        Self {
            unlock: default_unlock_script(),
            locks: None,
            ops: Vec::new(),
        }
    }
}

/// Build the next unsigned entry from `plog`'s verified head.
pub fn prepare_next_entry(plog: &Log, spec: NextEntrySpec) -> Result<UnsignedUpdate, Error> {
    let (_, last_entry, _) = plog
        .verify()
        .last()
        .ok_or_else(|| Error::PlogVerifyFailed("empty provenance log".into()))??;

    let locks = match spec.locks {
        Some(l) => l,
        None => last_entry.locks().cloned().collect(),
    };

    let mut mutable_entry = Entry::builder()
        .version(ENTRY_VERSION)
        .vlad(last_entry.vlad().clone())
        .prev(last_entry.cid())
        .seqno(last_entry.seqno() + 1)
        .locks(locks)
        .unlock(spec.unlock)
        .build();

    for params in &spec.ops {
        let op = op_from_params(params)?;
        mutable_entry.add_op(&op);
    }

    let curr_seqno = last_entry.seqno() + 1;
    if curr_seqno.is_lipmaa() {
        let lipmaa = curr_seqno.lipmaa();
        let longhop_entry = plog.seqno(lipmaa)?;
        mutable_entry.with_lipmaa(&longhop_entry.cid());
    }

    let unsigned_entry = mutable_entry.prepare_unsigned_entry()?;
    let message: Vec<u8> = unsigned_entry.clone().into();
    Ok(UnsignedUpdate {
        entry: unsigned_entry,
        message,
    })
}

/// Finalize `unsigned` with a Multisig proof and append to `plog` (verifies on append).
pub fn commit_with_multisig(plog: &mut Log, unsigned: Entry, signature: Multisig) -> Result<Entry, Error> {
    let proof: Vec<u8> = signature.into();
    let entry = unsigned.try_build_with_proof(proof)?;
    plog.try_append(&entry)?;
    Ok(entry)
}

/// Inherit head locks, drop any whose path equals `drop_path`, optionally push `add`.
pub fn locks_replacing_path(
    head: &Entry,
    drop_path: &Key,
    add: Option<Script>,
) -> Vec<Script> {
    let mut out: Vec<Script> = head
        .locks()
        .filter(|s| s.path() != *drop_path)
        .cloned()
        .collect();
    if let Some(script) = add {
        out.push(script);
    }
    out
}

/// Convert a Multikey public key into a `UseKey` op at `key`.
pub fn use_key_op(key: Key, mk: Multikey) -> OpParams {
    OpParams::UseKey { key, mk }
}

fn op_from_params(params: &OpParams) -> Result<provenance_log::Op, Error> {
    let built = match params {
        OpParams::Noop { key } => op::Builder::new(OpId::Noop)
            .with_key_path(key)
            .try_build()?,
        OpParams::Delete { key } => op::Builder::new(OpId::Delete)
            .with_key_path(key)
            .try_build()?,
        OpParams::UseCid { key, cid } => {
            let v: Vec<u8> = cid.clone().into();
            op::Builder::new(OpId::Update)
                .with_key_path(key)
                .with_data_value(v)
                .try_build()?
        }
        OpParams::UseKey { key, mk } => {
            let v: Vec<u8> = mk.clone().into();
            op::Builder::new(OpId::Update)
                .with_key_path(key)
                .with_data_value(v)
                .try_build()?
        }
        OpParams::UseStr { key, s } => op::Builder::new(OpId::Update)
            .with_key_path(key)
            .with_string_value(s)
            .try_build()?,
        OpParams::UseBin { key, data } => op::Builder::new(OpId::Update)
            .with_key_path(key)
            .with_data_value(data)
            .try_build()?,
        OpParams::KeyGen { .. } | OpParams::CidGen { .. } => {
            return Err(Error::InvalidOp(
                "KeyGen/CidGen must be resolved by BetterSign before entry assembly".into(),
            ));
        }
    };
    Ok(built)
}

/// Head CID of `plog` as multibase, if the log has a head entry.
#[allow(dead_code)]
pub fn head_cid(plog: &Log) -> Cid {
    plog.head.clone()
}

