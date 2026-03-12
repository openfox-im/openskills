---
name: crypto-schnorr
description: "TOS-variant Schnorr signatures on Ristretto255 with deterministic and batch verification. Use when: TOS transaction signing, TOS-compatible signature generation, batch signature verification. NOT for: standard Ed25519 signing, Bitcoin Schnorr (BIP-340), or non-TOS protocols."
license: MIT
requires:
  bins:
    - node
provider-backends:
  sign:
    entry: scripts/sign.mjs
    description: "Generate TOS Schnorr signatures"
  verify:
    entry: scripts/verify.mjs
    description: "Verify TOS Schnorr signatures"
---

This skill implements a custom TOS-variant Schnorr signature scheme on the Ristretto255 group. This is NOT standard Ed25519 Schnorr — the construction differs in how the public key is derived and how challenges are computed. The public key is computed as `priv^(-1) * H`, where H is the Pedersen blinding generator (not the standard basepoint). The challenge is derived as `SHA3-512(PK || msg || r)`, binding the public key, message, and nonce commitment together. Signatures are deterministic.

Use this skill when interacting with the TOS protocol's native signature scheme. The sign backend takes a private key and message and returns a Schnorr signature. The verify backend accepts a public key, message, and signature. Batch verification is supported — pass an array of tuples for faster aggregate verification using random linear combinations. All group operations use Ristretto255 to ensure a prime-order group without cofactor complications.

Header reference: `lib/include/at/crypto/at_schnorr.h`. Security considerations: the non-standard derivation (inverse scalar times H) means keys from other Schnorr schemes are not interchangeable. Always use the dedicated key generation provided by this skill. The SHA3-512 challenge hash provides 256-bit security against collision attacks on the challenge space. Nonce generation is deterministic (derived from the private key and message) to prevent nonce-reuse vulnerabilities.
