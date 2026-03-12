---
name: crypto-aead
description: "Authenticated encryption — AES-128/256-GCM and ChaCha20-Poly1305 (RFC 8439). Use when: encrypting data with authentication, TLS record protection, secure message transport, file encryption with integrity. NOT for: hashing, signing, key exchange, or unauthenticated encryption (never use AES-CBC/CTR alone)."
license: MIT
requires:
  bins:
    - node
provider-backends:
  encrypt:
    entry: scripts/encrypt.mjs
    description: "Authenticated encryption with associated data"
  decrypt:
    entry: scripts/decrypt.mjs
    description: "Authenticated decryption with tag verification"
---

This skill provides authenticated encryption with associated data (AEAD) using two algorithm families: AES-GCM and ChaCha20-Poly1305. Use AES-GCM when hardware AES-NI acceleration is available or when TLS 1.3/QUIC compatibility is required. Use ChaCha20-Poly1305 (RFC 8439) as a portable alternative that performs well on platforms without AES hardware support. Both algorithms guarantee confidentiality and integrity — any tampering with the ciphertext or associated data is detected during decryption.

AES-GCM supports 128-bit and 256-bit keys with a 12-byte IV (initialization vector) and produces a 16-byte authentication tag. Multiple backend implementations are available: reference C, AES-NI, AVX2, and AVX-512, selected automatically based on CPU capabilities. ChaCha20-Poly1305 uses a 32-byte key, 12-byte nonce, and produces a 16-byte authentication tag. Both algorithms support associated data (AD) that is authenticated but not encrypted. The encrypt backend accepts a key, nonce/IV, plaintext, and optional AD, returning ciphertext with appended tag. The decrypt backend reverses the operation, failing if authentication fails.

Header references: `lib/include/at/crypto/at_aes_gcm.h`, `at_chacha20_poly1305.h`, `at_aes_base.h`, `at_chacha.h`, `at_poly1305.h`. Both one-shot and in-place encryption APIs are available. Security critical: never reuse a nonce with the same key — AES-GCM nonce reuse completely breaks authenticity and leaks plaintext via XOR. ChaCha20-Poly1305 has similar nonce-reuse consequences. For protocols requiring many messages under one key, use a nonce-misuse-resistant construction or derive per-message keys.
