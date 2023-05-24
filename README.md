# Identity-based signatures (IBS).

Pure rust implementations of identity-based signature algorithms.

### Supported schemes

Currently only the Galindo-Garcia scheme is supported.

### Features

| Feature   | Default? | Description                                                             |
| :-------- | :------: | :---------------------------------------------------------------------- |
| `serde`   |    ✓     | Enables `serde` serialization and deserialization for exported structs. |
| `zeroize` |    ✓     | Enables [`Zeroize`][zeroize-trait] for secret exported structs.         |
