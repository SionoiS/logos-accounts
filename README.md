# logos-accounts

BetterSign accounts with **pluggable key storage** (local software wallet or **Keycard** hardware), exposed as a **Logos module**.

This repository implements provenance-based identity (VLADs + provenance logs / p-logs) using the [BetterSign](https://github.com/cryptidtech/bs) (`bs`) stack. Long-lived signing can run in process (for tests and CI) or on a [Keycard](https://github.com/nxm-rs/keycard) via `nexum-keycard`. Peer modules use the surface published through [logos-rust-sdk](https://github.com/logos-co/logos-rust-sdk).

## What you get

| Layer | What |
|-------|------|
| **Wallet** | `KeycardWallet` implements BetterSign `KeyManager` + `MultiSigner` (hybrid crypto: software ephemerals, hardware `/pubkey`) |
| **Domain API** | `AccountsApi` — single-account create / load / update / path-read / export (multibase / JSON); only verified p-logs |
| **Local cache** | `AccountCache` — multi p-log registry keyed by SHA-256(VLAD); import / export / remove / clear |
| **Storage choice** | Caller picks `local` or `keycard` when creating or importing an account (no separate connect step) |
| **Logos module** | LIDL contract + `AccountsModuleImpl` plugin packaging |

## Dependencies

```toml
nexum-keycard   = { git = "https://github.com/nxm-rs/keycard", branch = "main" }
bs              = { git = "https://github.com/cryptidtech/bs", branch = "main" }
logos-rust-sdk  = { git = "https://github.com/logos-co/logos-rust-sdk", branch = "master" }
```

Optional Cargo feature: **`pcsc`** — real PC/SC Keycard transport (hardware tests are `#[ignore]`).

## Architecture

BetterSign defines extension points we implement rather than fork:

| Layer | Crate | Role |
|-------|-------|------|
| Generic traits | `bs-traits` | `Signer`, `Verifier`, `GetKey`, `EphemeralKey`, async/sync variants |
| Opinionated supertraits | `bs::config::{sync,asynchronous}` | `KeyManager<E>`, `MultiSigner<E>` fixed to `Key` / `Codec` / `Multikey` / `Multisig` |
| Reference wallet | `bs-wallets::memory::InMemoryKeyManager` | Software backend for local storage and tests |
| Orchestration | `bs::BetterSign`, `open_plog`, `update_plog` | Create/update p-logs |

```text
Logos host
  └─ AccountsModuleImpl  (LIDL)
        └─ AccountCache  (key = SHA-256(canonical multibase VLAD))
              ├─ local  → SoftwareAccountsApi (InMemoryKeyManager)
              └─ keycard → AccountsApi<KeycardWallet>  (pcsc)
                    └─ BetterSign open / update / verify
```

The module holds **many** cached p-logs at once. Account ops take the multibase VLAD as the first argument (`operation(vlad, …)`); there is no implicit “loaded” session. Internally the map is indexed by the same 32-byte VLAD hash used for Keycard binding.

Keycard is **secp256k1-only**, signs a **32-byte prehash**, and exports **public keys only** for normal operation.

### Hybrid crypto

Keycard cannot safely model destroy-after-use ephemeral keys required for VLAD binding:

| Key role | Storage | Mechanism |
|----------|---------|-----------|
| VLAD / first-entry ephemeral | Software one-shot | `prepare_ephemeral_signing` |
| Long-lived `/pubkey` | Keycard BIP32 path (default `m/44'/60'/0'/0/0`) | `export_key(PublicKeyOnly)` + `sign` on SHA-256 prehash |
| Verification | Software | Multikey `verify_view()` — no card I/O |

### Signing

1. `digest = SHA-256(data)`
2. Card `sign(digest, derivation_path, confirm=false)`
3. Build Multisig `Es256KMsig` from the signature bytes

## Key storage

Storage is selected when **creating** or **importing** an account.

| Method | Use case | Key material |
|--------|----------|--------------|
| **`local`** | Tests, CI, no hardware | In-memory Multikeys (`InMemoryKeyManager`) |
| **`keycard`** | Production hardware-backed accounts | Master key on card; one card ↔ one account lifecycle |

### Storage JSON (LIDL / module)

**Create — local**

```json
{ "method": "local" }
```

**Create — keycard** (virgin card; missing secrets are generated)

```json
{
  "method": "keycard",
  "pin": "123456",
  "puk": "123456789012",
  "pairing_password": "…",
  "derivation_path": "m/44'/60'/0'/0/0"
}
```

**Import — keycard** (use credentials returned from create)

```json
{
  "method": "keycard",
  "pin": "123456",
  "pairing_key_hex": "…",
  "pairing_index": 0
}
```

### Keycard lifecycle

Creating an account with keycard storage **requires a virgin card** and binds the card to that account:

1. SELECT + virgin check  
2. INIT (PIN / PUK / pairing password)  
3. Pair → open secure channel  
4. GENERATE KEY  
5. Open p-log (`BetterSign::new`)  
6. Store **`SHA-256(multibase VLAD)`** (32 bytes) on the card public record  

Import verifies that the on-card hash matches the p-log VLAD. Card identity is **not** written into the first p-log entry.

Keycard create responses include credentials (PIN, PUK, pairing key/index) so the host can persist them for later loads. Treat that JSON as sensitive.

To create a new account on a previously used card, factory-reset it first (e.g. via `nexum-keycard-cli`). Factory reset is not part of this module.

## Domain API

`AccountsApi<W>` is the **single-account** library service (generics stay inside the crate). Typical surface:

| Method | Responsibility |
|--------|----------------|
| `attach_wallet` / `SoftwareAccountsApi::software()` | Library: attach local or custom wallet |
| `create_account` | Open a new p-log (verified before return) |
| `create_account_on_virgin_keycard` | Full virgin Keycard create + VLAD hash tag |
| `load_account` / `load_account_on_keycard` | Load p-log; **full-chain verify required**; Keycard also checks VLAD hash |
| `update_account` / `update_account_ops` | Append ops, sign with `/pubkey` |
| `export_plog` / `vlad` / `get_value` | Identity, export, and path reads from verified KVP |
| `rotate_pubkey` | Library-only Keycard path rebind + plog KeyGen |

Only verified p-logs are held after create/load. `get_value(path)` materializes the head KVP (e.g. `"/pubkey"`, `"/profile/name"`).

Default open config uses secp256k1 for VLAD, first-entry, and `/pubkey`, with lock/unlock scripts matching BetterSign conventions:

- Lock: `check_signature("/pubkey", "/entry/")`
- Unlock: `push("/entry/"); push("/entry/proof")`

### Local p-log cache

`AccountCache` stores multiple operable accounts for the Logos module:

| Method | Responsibility |
|--------|----------------|
| `insert` / `insert_by_hash` | Upsert a session under the VLAD hash |
| `get` / `remove` / `clear` | Lookup / drop one / drop all |
| `key_from_multibase` / `key_from_vlad` | Canonical hash via `vlad_hash` |

Wire methods still pass **full multibase VLAD** strings; hashing is an implementation detail of the index.

## Logos module (LIDL)

Public contract (`rust-lib/logos_accounts_module.lidl`, version **3.0.0**):

```text
module logos_accounts_module {
  method create_account(storage_json: string) -> string

  method import_plog(plog_b64: string, storage_json: string) -> string
  method export_plog(vlad: string) -> string
  method remove_plog(vlad: string) -> string
  method clear_cache() -> string

  method update_account(vlad: string, ops_json: string) -> string
  method get_value(vlad: string, path: string) -> string

  event account_created(vlad: string)
  event account_updated(head_cid: string)
  event card_error(message: string)
}
```

| Method | Notes |
|--------|--------|
| `create_account` | Creates, **verifies**, and **inserts** into the cache; returns `vlad` for later ops |
| `import_plog` | Full-chain verify required; upserts by VLAD hash only on success |
| `export_plog` / `remove_plog` / `clear_cache` | Cache lifecycle |
| `update_account` | First arg is multibase VLAD |
| `get_value` | Read any logical path from the verified p-log KVP (`{"type":"str"|"bin","value":...}`) |

**Removed in 3.0.0:** `get_public_key` (use `get_value(vlad, "/pubkey")`), `verify_plog` (verify is mandatory on create/import), `verify_signature` (use Multikey libraries directly if needed).

Complex types cross the boundary as **strings** (JSON / multibase). Keycard create may return `keycard` credentials alongside `vlad` / `head_cid` / `pubkey`.

`AccountsModuleImpl` maps LIDL methods onto the local `AccountCache` and local or Keycard backends. Install hook: `logos_module_install()`.

### Packaging

| File | Role |
|------|------|
| `metadata.json` | Logos module metadata and codegen paths |
| `CMakeLists.txt` | `logos_module(NAME logos_accounts_module)` |
| `flake.nix` | Nix packaging via logos-module-builder |
| `rust-lib/generated/provider_gen.rs` | Checked-in LIDL provider scaffold |

## Repository layout

```text
logos-accounts/
  metadata.json
  CMakeLists.txt
  flake.nix
  rust-lib/
    Cargo.toml
    logos_accounts_module.lidl
    generated/provider_gen.rs
    src/
      lib.rs                 # crate root, re-exports, install hook
      module.rs              # AccountsModuleImpl (cache-backed LIDL)
      api.rs                 # AccountsApi (single-account domain)
      cache.rs               # AccountCache keyed by VLAD hash
      storage.rs             # StorageConfig JSON
      binding.rs             # VLAD hash binding helpers
      keycard_lifecycle.rs   # virgin init + pair + generate key
      keycard_session.rs     # shared Keycard handle, public data I/O
      wallet.rs              # KeycardWallet traits
      path_map.rs            # logical Key ↔ BIP32
      config.rs              # default open/update configs
      convert.rs             # Multikey / Multisig / prehash bridges
      encoding.rs            # multibase / hex IPC helpers
      verifier.rs            # software Multikey verify
      error.rs
```

## Design decisions

1. **Ephemeral keys stay in software**; Keycard holds long-lived `/pubkey` only.  
2. **secp256k1 only** for hardware-backed accounts.  
3. **SHA-256 prehash** before Keycard `sign` (matches Multikey Es256K).  
4. **Storage chosen at create/import** — no global connect lifecycle.  
5. **One virgin Keycard per account create**; card stores VLAD hash only for wrong-card detection.  
6. **LIDL types as encoded strings** (JSON / multibase).  
7. **Hardware tests optional** — CI does not require a physical card.  
8. **Local multi p-log cache** indexed by `SHA-256(canonical multibase VLAD)`; wire API still uses full VLAD.  
9. **No session load step for ops** — `operation(vlad, …)` addresses any cached account.

## Building and testing

```bash
cd rust-lib && cargo test
```

Software paths (local storage) run without hardware. Optional:

```bash
cargo test --features pcsc -- --ignored
```

Requires a PC/SC reader, a virgin or appropriately provisioned Keycard, and env vars for existing hardware tests (e.g. `KEYCARD_PIN`, `KEYCARD_PAIRING_KEY`, `KEYCARD_PAIRING_INDEX`).

Nix / builder packaging: use the repo `flake.nix` when `logos-module-builder` is available.

## Out of scope

- Factory-reset API inside the module (use `nexum-keycard-cli`)  
- PIN change, unpair UI, multi-account per card  
- Multi-threshold / Lamport VLAD paths  
- Encryption / secret-sharing traits  
- Network publication of p-logs (export only)  
- File-encrypted local keystore (local storage is in-memory for testing)  
- Automatic filesystem write-through of the p-log cache via `persistence_path` (in-process only)
