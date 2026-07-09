# logos-accounts

BetterSign accounts backed by **Keycard** hardware, exposed as a **Logos module**.

This repository will implement provenance-based identity (VLADs + provenance logs / p-logs) using the [BetterSign](https://github.com/cryptidtech/bs) (`bs`) stack, with cryptographic signing performed on a [Keycard](https://github.com/nxm-rs/keycard) via `nexum-keycard`, and the surface area published to other Logos modules through [logos-rust-sdk](https://github.com/logos-co/logos-rust-sdk).

## Status

| Phase | Description | Status |
|-------|-------------|--------|
| **1** | BetterSign Keycard integration (wallet traits) | **Done** (unit-tested; hardware tests optional/`#[ignore]`) |
| **2** | Domain API | **WIP** (not started) |
| **3** | Logos module exposure | **WIP** (not started) |

Phase 1 provides `KeycardWallet` implementing BetterSign async (and sync) `KeyManager` + `MultiSigner` with hybrid software-ephemeral / Keycard-long-lived crypto.

## Dependencies

```toml
nexum-keycard   = { git = "https://github.com/nxm-rs/keycard", branch = "main" }
bs              = { git = "https://github.com/cryptidtech/bs", branch = "main" }
logos-rust-sdk  = { git = "https://github.com/logos-co/logos-rust-sdk", branch = "master" }
```

## Architecture overview

BetterSign defines extension points we implement rather than fork:

| Layer | Crate | Role |
|-------|-------|------|
| Generic traits | `bs-traits` | `Signer`, `Verifier`, `GetKey`, `EphemeralKey`, sync/async variants, `AsyncKeyManager`, `AsyncMultiSigner` |
| Opinionated supertraits | `bs::config::{sync,asynchronous}` | `KeyManager<E>`, `MultiSigner<E>` fixed to `Key` / `Codec` / `Multikey` / `Multisig` |
| Reference wallet | `bs-wallets::memory::InMemoryKeyManager` | Full sync+async impl of both supertraits |
| Orchestration | `bs::BetterSign`, `open_plog`, `update_plog` | Create/update p-logs; consume `KeyManager` + `MultiSigner` |

Keycard (`nexum-keycard`) is **secp256k1-only**, signs a **32-byte prehash**, and does not need to export private keys for normal operation (`export_key` public-only + `sign`).

Delivery order:

1. **Keycard wallet traits** → plug into BetterSign
2. **Domain API** → IPC-friendly service (**WIP**)
3. **Logos module** → LIDL + plugin packaging (**WIP**)

---

## Phase 1 — BetterSign Keycard integration (traits)

**Goal:** A type that satisfies `bs::config::asynchronous::{KeyManager, MultiSigner}` (and preferably the sync pair) so it can be passed into `BetterSign::new` / `open_plog` / `update_plog` with **no changes to `bs`**.

### 1.1 Module layout (library first)

Keep a pure Rust library core before Logos packaging:

```
src/
  lib.rs
  error.rs                 # Error: BsCompatibleError + Keycard/APDU/IO
  convert.rs               # k256/Multikey/Multisig bridges
  path_map.rs              # provenance_log::Key ↔ BIP32 DerivationPath
  keycard_session.rs       # Arc<Mutex<Keycard<…>>> lifecycle
  wallet.rs                # KeycardWallet: KeyManager + MultiSigner
  verifier.rs              # Software Multikey verifier (optional helper)
```

Later (Phase 3) the crate moves under `rust-lib/` for the Logos builder layout; Phase 1 stays at repo root to iterate faster.

### 1.2 Concrete types (must match `bs::config`)

Associated types must be exactly:

| Trait associated type | Concrete type |
|----------------------|---------------|
| `KeyPath` | `provenance_log::Key` |
| `Codec` | `multicodec::Codec` |
| `Key` / `PubKey` | `multikey::Multikey` |
| `Signature` | `multisig::Multisig` (`bs::Signature`) |
| `Error` | project `Error` implementing `bs::error::BsCompatibleError` |

Reference: `bs-wallets` `memory.rs` and `async_memory.rs`.

### 1.3 Traits to implement

Implement on a single `KeycardWallet<T: CardTransport>` (mirrors `InMemoryKeyManager` doing both roles):

**Key management**

- `GetKey` + `bs_traits::sync::SyncGetKey`
- `bs_traits::asyncro::AsyncKeyManager` (async wrappers; optional `preprocess_vlad` no-op or persist VLAD)

**Signing**

- `Signer` + `EphemeralKey`
- `bs_traits::sync::SyncSigner` + `SyncPrepareEphemeralSigning`
- `bs_traits::asyncro::AsyncSigner` + `AsyncMultiSigner`

**Verification (software)**

- `Verifier` + `SyncVerifier` / `AsyncVerifier` — pure Multikey `verify_view()`; no card I/O.
- Verification is not required by `MultiSigner` for `open_plog` / `update_plog`, but is required product-wise to verify signatures in VLADs and p-logs using Multikeys stored in the log.

Blanket impls in `bs::config` then make `KeycardWallet` a `KeyManager` + `MultiSigner`.

### 1.4 Hybrid crypto model (critical design choice)

Keycard cannot safely model **destroy-after-use ephemeral keys** the way BetterSign requires for VLAD + first-entry binding.

| Key role | Path (convention) | Where it lives | How produced |
|----------|-------------------|----------------|--------------|
| VLAD ephemeral | (not stored) | **Software one-shot** | `prepare_ephemeral_signing` → software `Secp256K1Priv`, sign once, drop secret |
| First-entry ephemeral (`/entrykey`) | (not stored long-term) | **Software one-shot** | same |
| Long-lived advertised key (`/pubkey`) | mapped BIP32 path (e.g. `m/44'/60'/0'/0/0`) | **Keycard** | `get_key` → `export_key(PublicKeyOnly)` → Multikey pub |
| Subsequent entry proofs | `entry_signing_key` usually `/pubkey` | **Keycard** | `try_sign` → card `sign` |

This matches `open_plog` / `update_plog` usage:

- **Open:** two `prepare_ephemeral_signing` calls (VLAD + first entry) + `key_manager.get_key` for `/pubkey`.
- **Update:** `signer.try_sign(entry_signing_key, entry_bytes)` with `/pubkey` after first-entry key is removed.

**Config constraint:** all codecs must be secp256k1 (`Codec::Secp256K1Priv` for keygen params). Ed25519 from upstream tests is **not** supported on Keycard.

### 1.5 Signing / Multisig conversion

Keycard `sign` requires exactly 32 bytes. Multikey secp256k1 software signing uses k256 `try_sign(msg)`, which **SHA-256-hashes** the message first, then ECDSA-signs. Match that:

1. `digest = SHA-256(data)`
2. `card.sign(&digest, &derivation_path, confirm=false)`
3. Build `Multisig` with `ms::Builder::new(Codec::Es256KMsig).with_signature_bytes(&sig.to_bytes()).try_build()`
4. Optionally verify with exported Multikey public key before returning

Public key export path:

1. `export_key(ExportOption::PublicKeyOnly, path)` → `k256::PublicKey`
2. Compressed SEC1 (33 bytes) into Multikey attributes with `Codec::Secp256K1Pub`
3. Fingerprint path mapping like `InMemoryKeyManager` (`paths: Key → fingerprint`, `keys: fingerprint → Multikey pub`)

### 1.6 Session and path map

```rust
// Conceptual shape
struct KeycardWallet<T: CardTransport> {
    card: Arc<Mutex<Keycard<CardExecutor<KeycardSecureChannel<T>>>>>,
    /// logical plog path → BIP32 path on card
    path_map: Mutex<HashMap<Key, DerivationPath>>,
    /// path → public Multikey cache (never private material from card)
    pub_cache: Mutex<HashMap<Key, Multikey>>,
}
```

- Construction: follow `nexum-keycard-signer::KeycardSigner::with_known_credentials` (PIN + pairing key/index + transport).
- Default map `/pubkey` → configurable derivation path (default `m/44'/60'/0'/0/0`).
- `get_key` for unmapped paths: prefer explicit registration (reject or allocate policy TBD).
- `prepare_ephemeral_signing`: **ignore the card**; generate software key with `multikey::Builder::new_from_random_bytes(Codec::Secp256K1Priv, …)` and a `FnOnce` signer. Reject non-secp256k1 codecs.

### 1.7 Error type

Must implement `BsCompatibleError`:

- `From<OpenError, UpdateError, PlogError, io::Error, multicid::Error, multikey::Error, multihash::Error, bs::Error>`
- `Debug` + `ToString`
- Plus `From<nexum_keycard::Error>` / transport errors

### 1.8 Dependencies to add (Phase 1)

Beyond existing git deps:

- Explicit: `bs-traits`, `multikey`, `multisig`, `multicodec`, `multicid`, `multihash`, `provenance-log`
- `nexum-apdu-core` (transport bounds)
- Optional feature `pcsc`: `nexum-apdu-transport-pcsc`
- `bip32`, `k256`, `sha2`, `thiserror`, `tokio` (`sync` mutex), `tracing`
- Dev: mock transport / software-only tests; hardware tests gated on `pcsc`

### 1.9 Phase 1 verification

- Unit tests: software-only ephemeral + Multikey verify roundtrip (no card)
- Unit tests: convert helpers (SEC1 ↔ Multikey, signature ↔ Multisig, SHA-256 prehash)
- Optional `#[ignore]` hardware test: open plog + update on real Keycard; `plog.verify()` succeeds
- Compile-time check: `fn assert_wallet<W: KeyManager<E> + MultiSigner<E>>()`

---

## Phase 2 — Domain API (**WIP**)

> **Status: WIP.** Design draft only; implement after Phase 1 wallet traits are solid.

**Goal:** A small, IPC-friendly service API that other code (and later LIDL) calls, without exposing trait generics across the module boundary.

### 2.1 Service type

```text
AccountsApi
  owns: KeycardWallet, BetterSign<KeycardWallet, KeycardWallet, Error> (or Option until open)
  config defaults: secp256k1 open/update scripts matching bs tests
```

Suggested methods (serialize-friendly; binary as `Vec<u8>` or multibase `String`):

| Method | Responsibility |
|--------|----------------|
| `connect(pin, pairing_key, pairing_index)` | Build session / secure channel |
| `card_status()` | App status / key UID / path |
| `ensure_key(derivation_path)` | Map `/pubkey` and confirm export |
| `create_account()` | `BetterSign::new(open_config, km, signer)` → VLAD + head CID + first entry |
| `load_account(plog_bytes)` | Deserialize `Log`, wrap in `BetterSign::from_parts` |
| `update_account(ops…)` | `BetterSign::update` with entry signing key `/pubkey` |
| `rotate_pubkey(new_path or generate)` | Update ops + path map (rotation policy TBD) |
| `vlad()` / `public_key()` | Read current identity material |
| `verify_entry` / `verify_plog()` | Software verify via Multikey + `plog.verify()` |
| `verify_signature(pubkey, msg, multisig)` | Direct Multikey verify (VLAD/plog proof helper) |
| `export_plog()` | Serialize log for persistence |

### 2.2 Default open config

Mirror `bs` tests but with **secp256k1**:

- `VladParams` + `FirstEntryKeyParams` + `PubkeyParams` all `Codec::Secp256K1Priv`
- Lock: `check_signature("/pubkey", "/entry/")`
- Unlock: `push("/entry/"); push("/entry/proof")`

### 2.3 Persistence hooks

- Pairing material and plog paths prepared for Logos `instance_persistence_path` (Phase 3); Phase 2 can use explicit paths or memory only.
- Never persist private keys (card holds them).

### 2.4 Phase 2 verification

- Integration test: create → update → verify chain → export/import
- Property: VLAD signature verifies against first-entry VLAD key material; entry proofs verify against `/pubkey`

---

## Phase 3 — Logos module exposure (**WIP**)

> **Status: WIP.** Design draft only; implement after Phase 2 API is usable.

**Goal:** Wrap the API as a loadable Logos plugin so peer modules get a **typed client** from LIDL.

### 3.1 Repo reshape (Logos builder path)

Follow `logos-rust-sdk` doctest `rust-calc` layout:

```
logos-accounts/
  metadata.json
  CMakeLists.txt
  flake.nix
  rust-lib/
    Cargo.toml              # name = logos_accounts, crate-type = ["staticlib"]
    logos_accounts_module.lidl
    src/
      lib.rs                # include generated scaffold; impl trait; logos_module_install
      … (Phase 1–2 modules)
    generated/              # provider_gen.rs produced by builder (or gitignored)
```

Root package today becomes `rust-lib/`. Builder supplies/pins `logos-rust-sdk` in production builds; keep an explicit git dep for local `cargo test` of the lib alone.

### 3.2 LIDL contract (public surface)

Draft contract (names may change):

```text
module logos_accounts_module {
  version "1.0.0"
  description "BetterSign accounts backed by Keycard hardware"

  method connect(pin: string, pairing_key_hex: string, pairing_index: int) -> string
  method card_status() -> string

  method create_account() -> string          // JSON: vlad, head_cid, pubkey
  method load_account(plog_b64: string) -> string
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

LIDL is the ABI other Logos modules depend on. Complex types cross the boundary as **strings** (JSON / multibase) for language neutrality.

### 3.3 Provider impl

```rust
include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

struct AccountsModuleImpl {
    api: AccountsApi, // or Option / OnceLock for lazy connect
}

impl LogosAccountsModule for AccountsModuleImpl {
    // map LIDL methods → AccountsApi
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<AccountsModuleImpl>();
}
```

Use generated `context()` for `instance_persistence_path` to store pairing info + last plog export.

### 3.4 Packaging files

- **`metadata.json`**: `interface: "cdylib"`, `codegen.lidl` + `codegen.rust`, PC/SC native libs as needed
- **`CMakeLists.txt`**: `logos_module(NAME logos_accounts_module)` via `LogosModule.cmake`
- **`flake.nix`**: `logos-module-builder` + `logos-rust-sdk` inputs; `mkLogosModule`

### 3.5 Consuming from other modules

```rust
// Concrete dependency
modules().logos_accounts_module.create_account()...

// Or interface bind if an interface contract is published later
// LogosAccountsClient::bind("logos_accounts_module")...
```

### 3.6 Phase 3 verification

- `cargo test` in `rust-lib` (unit + API)
- Builder / `nix build` of the module package when toolchain available
- Optional caller module exercising `create_account` / `verify_plog` through logoscore

---

## Critical files

| Path | Action |
|------|--------|
| `Cargo.toml` / later `rust-lib/Cargo.toml` | Expand deps; features `pcsc`, `sync` |
| `src/wallet.rs` (etc.) | Keycard trait implementations |
| `src/api.rs` | Domain API (**Phase 2 WIP**) |
| `rust-lib/logos_accounts_module.lidl` | Public Logos contract (**Phase 3 WIP**) |
| `rust-lib/src/lib.rs` | Module trait impl + install hook (**Phase 3 WIP**) |
| `metadata.json`, `CMakeLists.txt`, `flake.nix` | Logos packaging (**Phase 3 WIP**) |

## Existing code to reuse

| What | Where |
|------|--------|
| Trait surface & associated-type targets | `bs-traits`, `bs::config::{sync,asynchronous}` |
| Reference wallet behavior | `bs-wallets::memory::InMemoryKeyManager` (+ `async_memory`) |
| Open/update orchestration | `bs::BetterSign`, `bs::ops::{open,update}` |
| Sync→async adapters | `bs::config::adapters::{SyncToAsyncManager,SyncToAsyncSigner}` |
| Card session + sign/export | `nexum_keycard::Keycard`, `ExportOption`, `sign` |
| Session pattern | `nexum-keycard-signer::KeycardSigner` (pattern only; no Ethereum types in core wallet) |
| Multisig/Multikey secp256k1 | `multikey` secp256k1 views, `Codec::Es256KMsig` |
| Logos provider authoring | SDK doctest `rust-calc` (`trait impl` + `logos_module_install` + `metadata.json`) |

## Decisions locked in

1. **Ephemeral keys stay in software**; Keycard is for long-lived `/pubkey` signing only (VLAD security model requires destroyable ephemeral secrets).
2. **secp256k1 only** for hardware-backed accounts.
3. **SHA-256 prehash** before Keycard `sign` to match Multikey Es256K verification.
4. **Cross-module types as encoded strings** in LIDL v1 (JSON/multibase), not raw Multikey structs.
5. **Hardware tests optional/gated**; CI should not require a physical card.

## Out of scope (initial delivery)

- Full Keycard lifecycle UI (init/pair/PIN change) beyond connect with known credentials (use `nexum-keycard-cli`)
- Multi-threshold / Lamport VLAD paths
- Encryption / secret-sharing traits (`Encryptor` / `SecretSplitter`)
- IPFS/DHT publication of plogs (local/export only at first)
