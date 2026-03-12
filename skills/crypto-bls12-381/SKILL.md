---
name: crypto-bls12-381
description: "BLS12-381 pairing curve operations — G1/G2 point arithmetic, scalar multiply, and batch pairing. Use when: BLS signature aggregation, zkSNARK verification, Ethereum 2.0 operations, threshold cryptography. NOT for: general-purpose signing (use ed25519/secp256k1), non-pairing ECC, or when BN254 is required."
license: MIT
metadata: { "openfox": { "requires": { "bins": ["node"] }, "provider-backends": { "pairing": { "entry": "scripts/pairing.mjs", "description": "BLS12-381 pairing and point operations" } } } }
---

This skill provides elliptic curve operations on the BLS12-381 pairing-friendly curve, widely used in BLS signatures, zero-knowledge proof systems (Groth16, PLONK), and Ethereum 2.0 consensus. Operations include G1 and G2 point decompression, validation (subgroup checks), addition, subtraction, negation, and scalar multiplication. The pairing operation computes the optimal Ate pairing `e(P, Q)` for points P in G1 and Q in G2, with batch support for up to 8 pairs in a single call for efficient multi-pairing checks.

The pairing backend accepts operation type and operands. For point arithmetic, provide compressed or uncompressed point representations along with the desired operation. For pairing, provide arrays of G1 and G2 points (up to 8 pairs). Both big-endian and little-endian scalar representations are supported. Points are validated for subgroup membership before operations to prevent invalid curve attacks. The backend also exposes the scalar field for modular arithmetic operations needed by higher-level proof verification.

Header reference: `lib/include/at/crypto/at_bls12_381.h`. BLS12-381 provides approximately 128 bits of security. G1 points are 48 bytes compressed, G2 points are 96 bytes compressed. The pairing operation is computationally expensive — use batch pairing where possible to amortize the cost of the final exponentiation. This skill provides the low-level curve operations; for BLS signature aggregation or ZK proof verification, compose these primitives according to the relevant protocol specification. The implementation includes a VM syscall interface for use within the TOS virtual machine.
