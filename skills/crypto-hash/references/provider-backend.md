# crypto-hash — hash backend

## Input
- `request.algorithm` — Hash algorithm (sha256, sha512, sha3-256, keccak256, blake2b, blake3, sha1, ripemd160)
- `request.data` — Hex-encoded input data
- `request.encoding` — Optional: "hex" or "utf8"

## Output
- `hash` — Hex-encoded hash result (prefixed with 0x)
- `algorithm` — Algorithm used
- `bytes` — Output hash length in bytes
- `backend` — "skill:crypto-hash.hash"
