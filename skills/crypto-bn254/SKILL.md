---
name: crypto-bn254
description: "BN254 (alt_bn128) pairing curve for zkSNARK verification and EVM precompiles. Use when: Ethereum ecPairing precompile (0x08), Groth16 proof verification, EVM-compatible zkSNARK operations. NOT for: new deployments preferring BLS12-381, non-EVM chains, or general-purpose ECC."
license: MIT
metadata: { "openfox": { "requires": { "bins": ["node"] }, "provider-backends": { "pairing": { "entry": "scripts/pairing.mjs", "description": "BN254 pairing and point operations" } } } }
---

This skill provides elliptic curve operations on the BN254 curve (also known as alt_bn128), the pairing-friendly curve used by Ethereum's precompiled contracts at addresses 0x06 (ecAdd), 0x07 (ecMul), and 0x08 (ecPairing). Use this skill for zkSNARK proof verification (Groth16), on-chain verifier contracts, and any application requiring Ethereum EVM precompile compatibility. Operations include G1 point addition, scalar multiplication, and pairing checks.

The pairing backend supports G1 points (64 bytes uncompressed: 32-byte x, 32-byte y) and G2 points (128 bytes: two 64-byte field extension elements). Pairing checks accept up to 16 pairs of (G1, G2) points, computing the product of pairings and checking whether it equals the identity in the target group. Scalar field operations are also available for witness computation and proof element manipulation. The backend accepts an operation specifier (add, mul, pairing) along with the encoded point and scalar data.

Header references: `lib/include/at/crypto/at_bn254.h`, `at_bn254_internal.h`, `at_bn254_scalar.h`. BN254 provides approximately 100 bits of security (lower than the originally estimated 128 bits due to advances in NFS attacks on the embedding degree). For new systems, consider BLS12-381 instead. However, BN254 remains essential for Ethereum compatibility since it is hardcoded into the EVM precompiles. Point inputs must be validated (on-curve check) before performing operations. Invalid points will cause the operation to fail, matching EVM precompile behavior.
