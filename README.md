# logos-accounts

BetterSign provenance-log accounts with pluggable key storage (**local** software wallet or **Keycard** hardware), packaged as a [Logos](https://github.com/logos-co) module.

Long-lived signing can run in-process (tests / CI) or on a [Keycard](https://github.com/nxm-rs/keycard) via `nexum-keycard`. Identity is VLAD + provenance log (p-log) from the [BetterSign](https://github.com/cryptidtech/bs) stack. Peer modules call the LIDL surface generated through [logos-rust-sdk](https://github.com/logos-co/logos-rust-sdk).

| Status | Detail |
|--------|--------|
| Crate | `logos_accounts` **0.1.0** (`rust-lib/`) |
| LIDL contract | `logos_accounts_module` **3.0.0** |
| Module metadata | `logos_accounts_module` **1.0.0** (`metadata.json`) |
| Key storage | `local` (default for CI) or `keycard` (`pcsc` feature) |
| Cache | In-process multi-account `AccountCache`, keyed by `SHA-256(VLAD)` |

## Architecture

```text
Logos host
  └─ AccountsModuleImpl  (LIDL)
        └─ AccountCache  (key = SHA-256(canonical multibase VLAD))
              ├─ local   → SoftwareAccountsApi (InMemoryKeyManager)
              └─ keycard → AccountsApi<KeycardWallet>  (pcsc)
                    └─ BetterSign open / update / verify
```

- **Wallet** — `KeycardWallet` implements BetterSign `KeyManager` + `MultiSigner` (software ephemerals, hardware `/pubkey`).
- **Domain API** — `AccountsApi` is single-account: create / load / update / path-read / export. Only verified p-logs are retained.
- **Cache** — the Logos module holds many accounts; ops take the multibase VLAD as the first argument (`operation(vlad, …)`). No implicit “loaded” session.
- **Storage** — chosen at create/import via JSON (`local` or `keycard`). No separate connect step.

### Hybrid crypto (Keycard)

Keycard is secp256k1-only, signs a 32-byte SHA-256 prehash, and exports public keys only in normal use.

| Key role | Storage | Mechanism |
|----------|---------|-----------|
| VLAD / first-entry ephemeral | Software one-shot | `prepare_ephemeral_signing` |
| Long-lived `/pubkey` | Keycard BIP32 (default `m/44'/60'/0'/0/0`) | `export_key` + `sign` on prehash |
| Verification | Software | Multikey `verify_view()` — no card I/O |

## Logos module (LIDL 3.0.0)

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

| Method | Behavior |
|--------|----------|
| `create_account` | Opens p-log, verifies, inserts into cache; returns `vlad` (+ optional Keycard credentials) |
| `import_plog` | Full-chain verify required; upserts by VLAD hash only on success |
| `export_plog` / `remove_plog` / `clear_cache` | Cache lifecycle |
| `update_account` | Append ops signed with `/pubkey` |
| `get_value` | Read any path from the verified head KVP (`{"type":"str"\|"bin","value":...}`) |

Types cross the LIDL boundary as encoded strings (JSON / multibase). Errors are JSON `{"error":"..."}`.

### Storage JSON

**Local**

```json
{ "method": "local" }
```

**Keycard create** (virgin card; missing secrets are generated)

```json
{
  "method": "keycard",
  "pin": "123456",
  "puk": "123456789012",
  "pairing_password": "…",
  "derivation_path": "m/44'/60'/0'/0/0"
}
```

**Keycard import** (credentials from create)

```json
{
  "method": "keycard",
  "pin": "123456",
  "pairing_key_hex": "…",
  "pairing_index": 0
}
```

Keycard create initializes a virgin card, generates the master key, opens the p-log, and stores `SHA-256(VLAD)` on the card for wrong-card detection. Create responses may include sensitive Keycard credentials — persist them carefully. Factory reset is not in this module (use `nexum-keycard-cli`).

## Dependencies

```toml
nexum-keycard   = { git = "https://github.com/nxm-rs/keycard", branch = "main" }
bs              = { git = "https://github.com/cryptidtech/bs", branch = "main" }
logos-rust-sdk  = { git = "https://github.com/logos-co/logos-rust-sdk", branch = "master" }
```

Optional feature: **`pcsc`** — real PC/SC Keycard transport (hardware tests are `#[ignore]`).

## Repository layout

```text
logos-accounts/
  metadata.json              # Logos module metadata + codegen paths
  CMakeLists.txt             # logos_module(NAME logos_accounts_module)
  flake.nix                  # Nix packaging via logos-module-builder
  rust-lib/
    Cargo.toml
    logos_accounts_module.lidl
    generated/provider_gen.rs
    src/
      lib.rs                 # crate root, re-exports, logos_module_install
      module.rs              # AccountsModuleImpl (cache-backed LIDL)
      api.rs                 # AccountsApi (single-account domain)
      cache.rs               # AccountCache by VLAD hash
      storage.rs             # StorageConfig JSON
      wallet.rs              # KeycardWallet
      keycard_lifecycle.rs   # virgin init + pair + keygen + VLAD bind
      keycard_session.rs     # shared card handle
      binding.rs             # VLAD hash helpers
      path_map.rs            # logical Key ↔ BIP32
      config.rs / convert.rs / encoding.rs / verifier.rs / error.rs
```

## Building and testing

```bash
cd rust-lib && cargo test
```

Local storage paths run without hardware. With a reader and Keycard:

```bash
cargo test --features pcsc -- --ignored
```

Env vars used by hardware tests include `KEYCARD_PIN`, `KEYCARD_PAIRING_KEY`, and `KEYCARD_PAIRING_INDEX`.

Nix packaging: `flake.nix` builds via `logos-module-builder` when available.

## Out of scope (current)

- Factory-reset API (use external tooling)
- PIN change, unpair UI, multi-account per card
- Multi-threshold / Lamport VLAD paths
- Encryption / secret-sharing
- Network publication of p-logs (export only)
- Encrypted on-disk keystore (local storage is in-memory)
- Automatic p-log write-through to `persistence_path` (path is accepted as a hint; cache remains in-process)
