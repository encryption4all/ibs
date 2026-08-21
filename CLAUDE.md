# ibs

Identity-based signatures: a pure-Rust `no_std` crate. `gg.rs` implements the
Galindo-Garcia scheme over Ristretto via `curve25519-dalek`. Published to
crates.io as `ibs`, released by hand.

PostGuard is end-to-end encrypted email and file sending built on identity-based
cryptography: you encrypt to someone's identity and they prove that identity to a
Private Key Generator to get a decryption key. This crate is one of the Rust
primitives underneath it, alongside `ibe` — `pg-core` uses it to produce sender
signatures, so a recipient can verify who encrypted a message.

## Repos to weigh before changing this one

- `encryption4all/postguard` — the root of the family, and this crate's only
  direct consumer: `pg-core` declares `ibs = "0.4.0"`. The coupling is crates.io,
  not the build, so a change here reaches PostGuard on a publish and a breaking
  one needs a bump there. `postguard`'s `COMPATIBILITY.md` is what such a change
  has to argue against.
- `encryption4all/ibe` — the sibling primitive, IBE on BLS12-381 over
  `pg-curve`. It shares no curve and no dependency stack with this crate, so a
  fix in one does not carry over to the other.
- `encryption4all/pdf-signature` — signs PDFs with identity-based signatures. It
  reaches this crate through `pg-core`, not as a direct dependency.
