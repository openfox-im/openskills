# crypto-secp256r1 — sign / verify backends

## sign

### Input
- `request.privateKey` — Hex-encoded 32-byte private key (64 hex chars)
- `request.messageHash` — Hex-encoded 32-byte message hash (64 hex chars)

### Output
- `signature` — Hex-encoded signature
- `recoveryId` — Recovery ID (0-3)
- `backend` — "skill:crypto-secp256r1.sign"

## verify

### Input
- `request.publicKey` — Hex-encoded public key
- `request.messageHash` — Hex-encoded message hash
- `request.signature` — Hex-encoded signature

### Output
- `valid` — Boolean verification result
- `backend` — "skill:crypto-secp256r1.verify"
