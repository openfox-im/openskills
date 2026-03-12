# OpenSkills — Cryptographic Algorithm Skills for AI Agents

Production-grade cryptographic primitives packaged as [agentskills.io](https://agentskills.io) standard skills. Extracted from the [Avatar](https://github.com/nicholasgasior/avatar) C crypto library — optimized, side-channel resistant, SIMD-accelerated.

## Skills

| Skill | Category | Backends | Status |
|-------|----------|----------|--------|
| **crypto-hash** | Hashing | `hash` | node:crypto |
| **crypto-ed25519** | Signing | `sign`, `verify` | node:crypto |
| **crypto-schnorr** | Signing | `sign`, `verify` | native only |
| **crypto-secp256k1** | Signing | `sign`, `verify` | node:crypto |
| **crypto-secp256r1** | Signing | `sign`, `verify` | node:crypto |
| **crypto-vrf** | VRF | `prove`, `verify` | native only |
| **crypto-aead** | Encryption | `encrypt`, `decrypt` | node:crypto |
| **crypto-x25519** | Key Exchange | `exchange`, `encrypt` | partial |
| **crypto-encoding** | Encoding | `encode`, `decode` | node:crypto |
| **crypto-bls12-381** | Pairing | `pairing` | native only |
| **crypto-bn254** | Pairing | `pairing` | native only |
| **crypto-rangeproofs** | ZK Proofs | `verify` | native only |
| **crypto-uno-proofs** | ZK Proofs | `verify` | native only |

**Status**: `node:crypto` = working JS fallback via Node.js built-in crypto. `native only` = requires compiled C library binding. `partial` = ECDH works via node:crypto, ElGamal requires native.

## Algorithms

### Hashing
SHA-256, SHA-512, SHA-3/Keccak-256, BLAKE2b, BLAKE3, SHA-1, RIPEMD-160, HMAC

### Digital Signatures
Ed25519 (RFC 8032), TOS-Schnorr (Ristretto255), SECP256K1 (Bitcoin/Ethereum), SECP256R1 (P-256/NIST)

### Authenticated Encryption
AES-128/256-GCM (TLS 1.3 compatible), ChaCha20-Poly1305 (RFC 8439)

### Key Exchange & Encryption
X25519 (RFC 7748), ElGamal on Ristretto255

### Pairing Curves
BLS12-381 (G1/G2/pairing), BN254/alt_bn128 (EVM precompile compatible)

### Zero-Knowledge Proofs
Bulletproofs range proofs (Merlin transcript), UNO confidential transaction proofs (shield, ciphertext validity, commitment equality, balance)

### Encoding
Base58 (optimized 32B/64B), Base64, Bech32 (TOS mainnet/testnet), Address serialization

### VRF
Schnorrkel-compatible verifiable random function (DLEQ proofs on Ristretto255)

## Repository Structure

```
openskills/
├── skills/                    # agentskills.io standard skills
│   ├── crypto-hash/
│   │   ├── SKILL.md           # Skill definition
│   │   ├── scripts/hash.mjs   # Provider backend
│   │   └── references/        # I/O contracts
│   ├── crypto-ed25519/
│   └── ...                    # 13 skills total
├── lib/                       # C crypto library
│   ├── include/at/crypto/     # Headers (76 files)
│   ├── src/                   # Source (33 modules)
│   └── CMakeLists.txt         # Build system
├── package.json
└── LICENSE
```

## Using as Agent Skills

Each skill directory can be installed independently by any agentskills.io compatible agent:

```bash
# Claude Code
claude skill install ./skills/crypto-ed25519

# Or reference directly in .agents/skills/
cp -r skills/crypto-hash .agents/skills/
```

## Building the C Library

```bash
cd lib
cmake -B build
cmake --build build
```

Produces `libopenskills-crypto.a`. SIMD backends (AVX2, AVX-512) are auto-detected at compile time.

## License

MIT
