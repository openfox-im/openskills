---
name: crypto-x25519
description: "X25519 Diffie-Hellman key exchange and ElGamal encryption on Curve25519. Use when: establishing shared secrets, ECDH key agreement, hybrid encryption, confidential value encryption. NOT for: signing (use ed25519), long-term key storage, or protocols requiring non-Curve25519 DH."
license: MIT
requires:
  bins:
    - node
provider-backends:
  exchange:
    entry: scripts/exchange.mjs
    description: "X25519 ECDH key agreement"
  encrypt:
    entry: scripts/encrypt.mjs
    description: "ElGamal encryption on Ristretto255"
---

This skill provides two key exchange and encryption primitives built on Curve25519. X25519 implements Elliptic Curve Diffie-Hellman (ECDH) key agreement as specified in RFC 7748. Given two parties with 32-byte private keys, each computes a 32-byte shared secret by multiplying their private key with the other party's public key. This shared secret can then be used to derive symmetric encryption keys. Use the exchange backend for TLS-style key negotiation, ephemeral key agreement, or any protocol requiring a shared secret between two parties.

The ElGamal encryption backend operates on the Ristretto255 group and is used for confidential transactions where values must be encrypted to a recipient's public key while remaining homomorphic. ElGamal ciphertexts consist of two Ristretto255 points and support additive homomorphism — encrypted values can be added together without decryption. The encrypt backend takes a public key and a value (or point), returning a ciphertext pair. Decryption requires the corresponding private key.

Header references: `lib/include/at/crypto/at_x25519.h`, `lib/include/at/crypto/at_elgamal.h`. X25519 private keys are 32 random bytes with clamping applied internally. Public keys are 32 bytes (u-coordinate on the Montgomery curve). The shared secret output should always be passed through a KDF (e.g., HKDF) before use as an encryption key. ElGamal on Ristretto255 provides IND-CPA security but not IND-CCA2 — combine with a MAC or use within a larger authenticated protocol for full security.
