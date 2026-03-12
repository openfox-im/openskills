---
name: crypto-hash
description: "Cryptographic hash functions — SHA-256, SHA-512, SHA-3/Keccak-256, BLAKE2b, BLAKE3, SHA-1, RIPEMD-160, HMAC. Use when: computing message digests, content fingerprints, Merkle tree nodes, HMAC authentication tags. NOT for: password hashing (use bcrypt/argon2), encryption, or key derivation (use HKDF)."
license: MIT
requires:
  bins:
    - node
provider-backends:
  hash:
    entry: scripts/hash.mjs
    description: "Compute cryptographic hashes with algorithm selection"
---

This skill provides a unified interface to a broad set of cryptographic hash functions. Use it whenever you need to compute a digest of arbitrary data. Supported algorithms and their output sizes are: SHA-256 (32 bytes), SHA-512 (64 bytes), SHA-3 (variable), Keccak-256 (32 bytes), BLAKE2b (up to 64 bytes), BLAKE3 (32 bytes default, variable via XOF mode), SHA-1 (20 bytes, legacy only), and RIPEMD-160 (20 bytes, legacy only). HMAC is available for SHA-256 and SHA-512 keyed authentication. The backend accepts an algorithm name, input data, and optional parameters such as output length for XOF-capable algorithms.

Both streaming (init/update/finalize) and one-shot APIs are supported. Streaming is preferred for large inputs or when data arrives incrementally. Batch processing is available for SHA-256 and Keccak-256 with SIMD acceleration (AVX/AVX-512) when the platform supports it — pass an array of inputs to hash them in parallel. For BLAKE3, the XOF mode allows requesting arbitrary output lengths beyond the default 32 bytes.

Header references: `lib/include/at/crypto/at_sha256.h`, `at_sha512.h`, `at_sha3.h`, `at_keccak256.h`, `at_blake2b.h`, `at_blake3.h`, `at_sha1.h`, `at_ripemd160.h`, `at_hmac.h`. Security note: SHA-1 and RIPEMD-160 are provided for backward compatibility (e.g., Bitcoin address derivation) and should not be used for new security-critical applications. Prefer SHA-256, BLAKE3, or Keccak-256 for collision resistance. SIMD-accelerated paths are selected automatically at runtime based on CPU feature detection.
