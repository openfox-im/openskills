# crypto-x25519 — exchange / encrypt backends

## exchange

### Input
- `request.privateKey` — Hex-encoded private key
- `request.peerPublicKey` — Hex-encoded peer public key

### Output
- `sharedSecret` — Hex-encoded shared secret
- `backend` — "skill:crypto-x25519.exchange"

## encrypt

### Input
- `request.publicKey` — Hex-encoded recipient public key
- `request.plaintext` — Hex-encoded plaintext

### Output
- `ciphertext` — Hex-encoded ciphertext
- `backend` — "skill:crypto-x25519.encrypt"
