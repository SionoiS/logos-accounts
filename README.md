# logos-accounts

BetterSign accounts with **pluggable key storage** (local software wallet or **Keycard** hardware), exposed as a **Logos module**.

This repository implements provenance-based identity (VLADs + provenance logs / p-logs) using the [BetterSign](https://github.com/cryptidtech/bs) (`bs`) stack. Long-lived signing can run in process (for tests and CI) or on a [Keycard](https://github.com/nxm-rs/keycard) via `nexum-keycard`. Peer modules use the surface published through [logos-rust-sdk](https://github.com/logos-co/logos-rust-sdk).

## What you get

| Layer | What |
|-------|------|
| **Wallet** | `KeycardWallet` implements BetterSign `KeyManager` + `MultiSigner` (hybrid crypto: software ephemerals, hardware `/pubkey`) |
| **Domain API** | `AccountsApi` — create / load / update / verify / export with multibase strings and JSON ops |
| **Storage choice** | Caller picks `local` or `keycard` when creating or loading an account (no separate connect step) |
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
        ├─ local  → SoftwareAccountsApi (InMemoryKeyManager)
        └─ keycard → AccountsApi<KeycardWallet>  (pcsc)
              └─ BetterSign open / update / verify
```

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

Storage is selected when **creating** or **loading** an account.

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

**Load — keycard** (use credentials returned from create)

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

Load verifies that the on-card hash matches the p-log VLAD. Card identity is **not** written into the first p-log entry.

Keycard create responses include credentials (PIN, PUK, pairing key/index) so the host can persist them for later loads. Treat that JSON as sensitive.

To create a new account on a previously used card, factory-reset it first (e.g. via `nexum-keycard-cli`). Factory reset is not part of this module.

## Domain API

`AccountsApi<W>` is the library service (generics stay inside the crate). Typical surface:

| Method | Responsibility |
|--------|----------------|
| `attach_wallet` / `SoftwareAccountsApi::software()` | Library: attach local or custom wallet |
| `create_account` | Open a new p-log |
| `create_account_on_virgin_keycard` | Full virgin Keycard create + VLAD hash tag |
| `load_account` / `load_account_on_keycard` | Load p-log; Keycard path checks VLAD hash |
| `update_account` / `update_account_ops` | Append ops, sign with `/pubkey` |
| `export_plog` / `vlad` / `public_key` | Identity and export |
| `verify_plog` / `verify_signature` | Software verification |
| `rotate_pubkey` | Library-only Keycard path rebind + plog KeyGen |

Default open config uses secp256k1 for VLAD, first-entry, and `/pubkey`, with lock/unlock scripts matching BetterSign conventions:

- Lock: `check_signature("/pubkey", "/entry/")`
- Unlock: `push("/entry/"); push("/entry/proof")`

## Logos module (LIDL)

Public contract (`rust-lib/logos_accounts_module.lidl`, version **1.1.0**):

```text
module logos_accounts_module {
  method create_account(storage_json: string) -> string
  method load_account(plog_b64: string, storage_json: string) -> string
  method update_account(ops_json: string) -> string
  method export_plog() -> string
  method get_vlad() -> string
  method get_public_key() -> string
  method verify_plog() -> bool
  method verify_signature(pubkey_b64: string, message_b64: string, sig_b64: string) -> bool

  event account_created(vlad: string)
  event account_updated(head_cid: string)
  event card_error(message: string)
}
```

Complex types cross the boundary as **strings** (JSON / multibase). Keycard create may return `keycard` credentials alongside `vlad` / `head_cid` / `pubkey`.

`AccountsModuleImpl` maps LIDL methods onto local or Keycard backends. Install hook: `logos_module_install()`.

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
      module.rs              # AccountsModuleImpl
      api.rs                 # AccountsApi
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
4. **Storage chosen at create/load** — no global connect lifecycle.  
5. **One virgin Keycard per account create**; card stores VLAD hash only for wrong-card detection.  
6. **LIDL types as encoded strings** (JSON / multibase).  
7. **Hardware tests optional** — CI does not require a physical card.

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
