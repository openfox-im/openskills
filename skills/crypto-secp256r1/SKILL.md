---
name: crypto-secp256r1
description: "SECP256R1 (P-256/NIST) ECDSA signatures for TLS and standard compliance. Use when: TLS certificate operations, FIPS-compliant signing, WebAuthn/FIDO2, Apple/Google platform cryptography. NOT for: blockchain signing (use secp256k1), Ed25519 protocols, or non-NIST curves."
license: MIT
requires:
  bins:
    - node
provider-backends:
  sign:
    entry: scripts/sign.mjs
    description: "Generate ECDSA signatures over P-256"
  verify:
    entry: scripts/verify.mjs
    description: "Verify ECDSA signatures over P-256"
---

This skill provides ECDSA signatures on the SECP256R1 curve (also known as P-256 or prime256v1), the NIST-standardized elliptic curve widely used in TLS certificates, WebAuthn/FIDO2, and government systems. Use this when interoperability with standard PKI infrastructure is required, as opposed to secp256k1 which is primarily used in cryptocurrency contexts.

The sign backend accepts a 32-byte private key and a message hash, producing an ECDSA signature. The verify backend takes a public key, message hash, and signature. Key sizes are 32 bytes for private keys and 64 bytes for uncompressed public key coordinates (x, y). The implementation uses the s2n-bignum library with precomputed multiplication tables for high performance, including optimized point multiplication via window-based methods.

Header reference: `lib/include/at/crypto/at_secp256r1.h`. The s2n implementation (`at_secp256r1_s2n.c`, `at_secp256r1_table.c`) provides constant-time scalar multiplication using precomputed tables to resist timing attacks. This curve is approved for use in FIPS 186-4 and is required by many compliance frameworks. Note that P-256 has a different security profile than Curve25519 — it relies on NIST-selected parameters, which some applications prefer to avoid in favor of curves with fully transparent parameter generation.
