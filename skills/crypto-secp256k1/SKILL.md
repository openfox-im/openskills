---
name: crypto-secp256k1
description: "SECP256K1 ECDSA signatures with public key recovery (Bitcoin/Ethereum compatible). Use when: signing Ethereum transactions, Bitcoin message signing, ECDSA with key recovery. NOT for: TLS/HTTPS (use secp256r1), Ed25519-based protocols, or non-ECDSA signature schemes."
license: MIT
metadata: { "openfox": { "requires": { "bins": ["node"] }, "provider-backends": { "sign": { "entry": "scripts/sign.mjs", "description": "Generate ECDSA signatures over secp256k1" }, "verify": { "entry": "scripts/verify.mjs", "description": "Verify ECDSA signatures over secp256k1" } } } }
---

This skill provides ECDSA signatures on the SECP256K1 curve, the standard used by Bitcoin, Ethereum, and many other blockchain systems. Private keys are 32 bytes (a scalar in the secp256k1 field). Signatures are 64 bytes (r, s components) with an optional recovery byte that allows reconstructing the signer's public key from the signature alone. This public key recovery capability is essential for Ethereum transaction verification where the sender address is derived from the recovered key.

The sign backend takes a 32-byte private key and a 32-byte message hash (typically a Keccak-256 digest for Ethereum or double-SHA-256 for Bitcoin) and returns a 64-byte signature plus a recovery ID. The verify backend accepts a public key, message hash, and signature. Alternatively, use the recovery mode to extract the public key from the signature and verify implicitly.

Header reference: `lib/include/at/crypto/at_secp256k1.h`. The implementation wraps libsecp256k1, which provides constant-time operations and has been extensively audited for use in production cryptocurrency systems. Always hash messages before signing — the sign function expects a 32-byte digest, not raw message data. Ensure the recovery ID is preserved when it is needed for on-chain verification (e.g., Ethereum's `ecrecover` precompile).
