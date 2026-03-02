# odin-secp256k1

Pure Odin implementation of elliptic curve cryptography on the secp256k1 curve.

Provides ECDSA signing, verification, and public key recovery — the core cryptographic operations needed for Ethereum and Bitcoin.

## Features

- secp256k1 field and scalar arithmetic
- Point addition, doubling, scalar multiplication
- ECDSA sign / verify / recover (ecrecover)
- RFC 6979 deterministic nonce generation
- Compressed and uncompressed public key serialization
- Constant-time operations where security-critical

## Status

Early development. Part of the [odiem-ecosystem](../).
