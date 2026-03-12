---
name: crypto-ed25519
description: "Ed25519 digital signatures with Curve25519 and Ristretto255 infrastructure. Use when: signing messages, verifying signatures, public-key authentication, batch verification. NOT for: encryption (use X25519+AEAD), Ethereum-style signing (use secp256k1), or key exchange (use crypto-x25519)."
license: MIT
requires:
  bins:
    - node
provider-backends:
  sign:
    entry: scripts/sign.mjs
    description: "Generate Ed25519 signatures"
  verify:
    entry: scripts/verify.mjs
    description: "Verify Ed25519 signatures with optional batch mode"
---

This skill implements Ed25519 digital signatures as specified in RFC 8032. Use it for general-purpose public-key signing and verification where speed and small key/signature sizes matter. Private keys are 32 bytes, public keys are 32 bytes (compressed Edwards point), and signatures are 64 bytes. Internally, Ed25519 uses SHA-512 for nonce derivation and challenge computation. The sign backend takes a private key (or seed) and a message, returning a 64-byte signature. The verify backend takes a public key, message, and signature, returning a boolean result.

Batch verification is supported: pass multiple (public key, message, signature) tuples for a single-message batch verify, which is faster than verifying each individually due to combined multi-scalar multiplication. The underlying field arithmetic uses the f25519 field (`lib/include/at/crypto/at_f25519.h`) and Curve25519 group operations (`at_curve25519.h`). Ristretto255 (`at_ristretto255.h`) is also available for applications requiring a prime-order group abstraction over Curve25519.

Header reference: `lib/include/at/crypto/at_ed25519.h`. The implementation includes constant-time scalar operations to prevent timing side-channels. Key generation derives the public key from a 32-byte seed via SHA-512 expansion and scalar clamping. Do not reuse seeds across different signature schemes (e.g., do not share a seed between Ed25519 and X25519 without proper domain separation).
