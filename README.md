# logos-accounts

BetterSign provenance-log **cache** packaged as a [Logos](https://github.com/logos-co) module. Identity is VLAD + provenance log (p-log) from the [BetterSign](https://github.com/cryptidtech/bs) stack. Users call the LIDL surface generated through [logos-rust-sdk](https://github.com/logos-co/logos-rust-sdk).

| Status | Detail |
|--------|--------|
| Crate | `logos_accounts` **0.1.0** (`rust-lib/`) |
| LIDL contract | `logos_accounts_module` **1.0.0** |
| Module metadata | `logos_accounts_module` **1.0.0** (`metadata.json`) |
| Keys | Ephemeral Multikey used at creation; all later signs are **external Multisig** |
| Cache | In-process multi-account `AccountCache`, keyed by `SHA-256(VLAD)` |

## Architecture

```text
User (holds root /pubkey secret)
  │  create_account(pubkey_multibase)
  ▼
logos-accounts  — ephemerals keys for VLAD + /entrykey
                — publishes user Multikey at /pubkey
  │  prepare_update | prepare_delegate | prepare_revoke
  │       → message_multibase + signing_key_path
  │  user Multikey.sign(entry-bytes)
  │  commit_update(signature_multibase)
  ▼
AccountCache → PlogAccount { log, pending challenges }
```

### Create

| Step | Key | Who |
|------|-----|-----|
| VLAD binding | Ephemeral Multikey | Module |
| First entry proof | Ephemeral `/entrykey` | Module |
| Long-lived `/pubkey` | User Multikey (public) | Caller supplies `pubkey_multibase` |

Root **private** keys never enter this module. Subsequent entries require external Multisig from `/pubkey` (or a delegated path key).

### Mutations (prepare / commit)

Every post-open write:

1. Prepare → challenge with `message_multibase` (unsigned entry bytes) and `signing_key_path`
2. User signs with Multikey (entry-bytes encoding)
3. `commit_update(vlad, challenge_id, signature_multibase)` → verified append

#### New entree — `prepare_update(vlad, request_json)`

Author the next entry's **locks** (policy for the *following* entry) and **ops** (KVP mutations).

```json
{
  "locks": "inherit",
  "ops": [
    { "op": "update", "key": "/profile/name", "value": { "str": "alice" } },
    { "op": "update", "key": "/avatar", "value": { "data": "u…" } },
    { "op": "delete", "key": "/profile/old" },
    { "op": "noop", "key": "/touch/" }
  ],
  "sign_as": "/pubkey"
}
```

| Field | Notes |
|-------|--------|
| `locks` | `"inherit"` (default), `{ "replace": [ { "path", "code" } ] }`, `{ "upsert": { "path", "code" } }`, `{ "remove": "/apps/chat/" }` |
| `ops` | `noop`, `delete` or `update` with `value`: `{ "str" }` or `{ "data" }` |
| `sign_as` | Optional Multikey path for the user; default `/pubkey` |


#### Helpers — `prepare_delegate` / `prepare_revoke`

| Method | Expands to |
|--------|------------|
| `prepare_delegate(vlad, path, pubkey_multibase)` | lock `upsert` for `path` + `update` `{path}pubkey` |
| `prepare_revoke(vlad, path)` | lock `remove` for `path` + `delete` `{path}pubkey` |

**Closest-parent signing:** among active path delegations, pick the longest **proper ancestor** of `path`; use `{ancestor}pubkey`. If none, use `/pubkey`.

Examples:
- no path → root
- only `/apps/` → nested `/apps/chat/` signs as `/apps/pubkey`
- sibling path `/other/` with only `/apps/` → root.

## Logos module (LIDL 1.0.0)

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
  method prepare_delegate(vlad: string, path: string, pubkey_multibase: string) -> string
  method prepare_revoke(vlad: string, path: string) -> string
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
| `create_account` | Ephemeral keys + external root Multikey; cache insert |
| `import_plog` | Full-chain verify; upsert by VLAD hash |
| `export_plog` / `remove_plog` / `clear_cache` | Cache lifecycle |
| `get_value` | Read path from verified head KVP |
| `list_delegations` | Active path → Multikey grants |
| `prepare_update` | Raw locks + ops for external Multisig |
| `prepare_delegate` / `prepare_revoke` | Sugar over lock + KV; closest-parent sign |
| `commit_update` | Append with Multisig proof |
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
- User UX for key generation / storage
- Factory reset or card administration
