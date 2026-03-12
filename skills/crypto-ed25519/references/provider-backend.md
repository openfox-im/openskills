# crypto-ed25519 — sign / verify backends

## sign

### Input
- `request.privateKey` — Hex-encoded 32-byte private key (64 hex chars)
- `request.message` — Hex-encoded message

### Output
- `signature` — Hex-encoded 64-byte signature (128 hex chars)
- `publicKey` — Hex-encoded 32-byte public key (64 hex chars)
- `backend` — "skill:crypto-ed25519.sign"

## verify

### Input
- `request.publicKey` — Hex-encoded public key
- `request.message` — Hex-encoded message
- `request.signature` — Hex-encoded signature

### Output
- `valid` — Boolean verification result
- `backend` — "skill:crypto-ed25519.verify"
