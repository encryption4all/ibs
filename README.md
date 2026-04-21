# <p align="center"><img src="./img/pg_logo.svg" height="128px" alt="PostGuard" /></p>

> For full documentation, visit [docs.postguard.eu](https://docs.postguard.eu/repos/ibs).

Pure Rust implementations of identity-based signature (IBS) algorithms. Currently implements the Galindo-Garcia scheme on Curve25519.

In the PostGuard ecosystem, this crate is used by `pg-core` to produce sender signatures so recipients can verify who encrypted a message.

### Supported schemes

Currently only the Galindo-Garcia scheme is supported.

### Features

| Feature   | Default? | Description                                                             |
| :-------- | :------: | :---------------------------------------------------------------------- |
| `serde`   |    yes   | Enables `serde` serialization and deserialization for exported structs. |
| `zeroize` |    yes   | Enables `Zeroize` for secret exported structs.                          |

## Development

Build the crate:

```sh
cargo build
```

Run all tests:

```sh
cargo test
```

Run benchmarks:

```sh
cargo bench
```

## Releasing

New versions are published manually to [crates.io](https://crates.io/crates/ibs). Bump the version in `Cargo.toml`, commit, tag, and run `cargo publish`.

## License

Dual-licensed at your option under either [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE). This is the standard Rust ecosystem licensing arrangement and is declared as `license = "MIT OR Apache-2.0"` in `Cargo.toml`.
