# logos-accounts

BetterSign provenance-log **cache** packaged as a [Logos](https://github.com/logos-co) module. This process **never holds long-lived private keys**.

| Status | Detail |
|--------|--------|
| Crate | `logos_accounts` **0.1.0** (`rust-lib/`) |
| LIDL contract | `logos_accounts_module` **5.0.0** |
| Module metadata | `logos_accounts_module` **1.0.0** (`metadata.json`) |
| Keys | Peer root Multikey at create; all later signs are **external Multisig** |
| Cache | In-process multi-account `AccountCache`, keyed by `SHA-256(VLAD)` |

Identity is VLAD + provenance log (p-log) from the [BetterSign](https://github.com/cryptidtech/bs) stack. Peer modules call the LIDL surface generated through [logos-rust-sdk](https://github.com/logos-co/logos-rust-sdk).

## Architecture

```text
Peer (holds root /pubkey secret)
  │  create_account(pubkey_multibase)
  ▼
logos-accounts  — software ephemerals for VLAD + /entrykey only (discarded)
                — publishes peer Multikey at /pubkey
  │  prepare_update → message_multibase
  │  peer Multikey.sign(entry-bytes)
  │  commit_update(signature_multibase)
  ▼
AccountCache → PlogAccount { log, pending challenges }
```

### Create (one-shot)

| Step | Key | Who |
|------|-----|-----|
| VLAD binding | Ephemeral Multikey | Module (discarded) |
| First entry proof | Ephemeral `/entrykey` | Module (discarded) |
| Long-lived `/pubkey` | Peer Multikey (public) | Caller supplies `pubkey_multibase` |

Root **private** keys never enter this module. Subsequent entries require external Multisig from `/pubkey` (or a delegated path key).

### Mutations (prepare / commit)

Every post-open write:

1. `prepare_update(vlad, request_json)` → challenge with `message_multibase` (unsigned entry bytes)
2. Peer signs with Multikey (entry-bytes encoding)
3. `commit_update(vlad, challenge_id, signature_multibase)` → verified append

`request_json` kinds:

```json
{ "kind": "ops", "ops": [ {"op":"use_str","key":"/profile/name","value":"alice"} ] }
{ "kind": "delegate", "path": "/apps/chat/", "pubkey_multibase": "…" }
{ "kind": "revoke", "path": "/apps/chat/" }
{ "kind": "path_ops", "path": "/apps/chat/", "ops": [ … ] }
```

## Logos module (LIDL 5.0.0)

```text
module logos_accounts_module {
  method create_account(pubkey_multibase: string) -> string
  method import_plog(plog_b64: string) -> string
  method export_plog(vlad: string) -> string
  method remove_plog(vlad: string) -> string
  method clear_cache() -> string
  method get_value(vlad: string, path: string) -> string
  method list_delegations(vlad: string) -> string
  method prepare_update(vlad: string, request_json: string) -> string
  method commit_update(vlad: string, challenge_id: string, signature_multibase: string) -> string
  method cancel_update(vlad: string, challenge_id: string) -> string

  event account_created(vlad: string)
  event account_updated(head_cid: string)
  event path_delegated(vlad: string, path: string)
  event path_revoked(vlad: string, path: string)
  event error(message: string)
}
```

| Method | Behavior |
|--------|----------|
| `create_account` | Ephemeral open + external root Multikey; cache insert |
| `import_plog` | Full-chain verify; upsert by VLAD hash |
| `export_plog` / `remove_plog` / `clear_cache` | Cache lifecycle |
| `get_value` | Read path from verified head KVP |
| `list_delegations` | Active path → Multikey grants |
| `prepare_update` / `commit_update` | External Multisig mutations |
| `cancel_update` | Drop a pending challenge |

Errors are JSON `{"error":"..."}` and also emit the `error` event.

## Development

```bash
cd rust-lib
cargo test
```

### Layout

```text
rust-lib/
  logos_accounts_module.lidl
  generated/provider_gen.rs
  src/
    api.rs              # PlogAccount: create / import / prepare / commit
    ephemeral_open.rs   # Transient open helper
    entry_update.rs     # Unsigned entry assembly
    cache.rs            # Multi-account VLAD-hash cache
    module.rs           # LIDL provider
    config.rs           # Open locks + path policy
    encoding.rs / convert.rs / verifier.rs / vlad_hash.rs
```

## Out of scope

- Holding long-lived private keys (wallets, HSMs, Keycard) inside this module
- Peer UX for key generation / storage
- Factory reset or card administration
