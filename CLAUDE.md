
---

## Agent notes (migrated from the dobby memory repo)

## Overview
`encryption4all/ibs` is a pure-Rust `no_std` identity-based signature library.
`gg.rs` implements Galindo-Garcia over Ristretto via `curve25519-dalek`.

## Release process
Manual release process, no automation.

## CI
`.github/workflows/ci.yml` jobs:
- **Lint**: `cargo fmt -- --check` only, no clippy.
- **Test**: `cargo test --release --all-features` on ubuntu / windows / macOS.
- **no-std**: `cargo build --target {wasm32-unknown-unknown, wasm32-wasip1}
  --all-features --lib`.
- **PR Title**: Conventional Commit check via
  `amannn/action-semantic-pull-request@v6`, `pr-title.yml`.

Always run `cargo fmt --all -- --check` and a wasm32 build before pushing.

## Dependency entanglement: curve25519-dalek gates the whole RustCrypto/rand stack
- `curve25519-dalek` is pinned to `=5.0.0-rc.1` (features `alloc`,
  `precomputed-tables`, `digest`, `rand_core`), which pins `rand_core 0.10` and
  `digest 0.11`. `Scalar::random(r)` and `Scalar::from_hash(h)` propagate those
  versions into `gg.rs`'s `setup`/`keygen`/`sign` API (all `<R: CryptoRng>`) and
  the `h_helper` Sha3_512 path.
- Current pins: `rand_core 0.10`, `sha3 0.12`, `shake 0.1`, `rand 0.10` (dev-dep).
  Bumping any of these was gated on `curve25519-dalek` 5.x; that migration landed
  in main via #24 (commit `0ebff0e`, `chore(deps): migrate to curve25519-dalek
  5.0, rand 0.10, sha3 0.12`).
- **Caveat: still on the release candidate.** `curve25519-dalek` 5.0 has not
  shipped stable, so the pin is `=5.0.0-rc.1`. Re-pin to the stable `5.0` once it
  lands; nothing else in the stack needs to change for that.
- Safe to bump independently: `criterion` (dev-dep only, no API touch, e.g.
  `std::hint::black_box` replacing the deprecated `criterion::black_box`).
- Tombstone: stay on `bincode` 2.x; see `rules/bincode-3-tombstone.md`. Do not
  bump to `bincode` 3.0.0.

## RustCrypto 2025/26 + rand 0.10 API migration facts
This stack moved to `curve25519-dalek` 5.x + `rand_core` 0.10 + `digest` 0.11 in
#24. The facts that made that migration work, kept here for the next bump:
- `Shake128`/`Shake256` moved out of `sha3` into a standalone `shake` crate
  (sha3 0.12 uses digest 0.11). Hence `shake = { version = "0.1", default-features
  = false }`; `Sha3_256`/`Sha3_512`/`Digest` stay in `sha3`.
- `rand_core 0.10`: `RngCore` is deprecated (use `Rng`); `CryptoRng: Rng` now, so
  bounding `<R: CryptoRng>` alone suffices. `dalek 5`'s `Scalar::random<R:
  CryptoRng>` follows this.
- `OsRng` was removed from `rand_core` (its `SysRng` successor only implements
  the fallible `TryRng`/`TryCryptoRng`, not `CryptoRng`). Tests/bench/doctests use
  `rand::rng()` (`ThreadRng`, an infallible `CryptoRng`); `rand::thread_rng()` is
  also removed.
