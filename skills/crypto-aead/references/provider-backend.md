# crypto-aead — encrypt / decrypt backends

## encrypt

### Input
- `request.algorithm` — AEAD algorithm (aes-256-gcm, chacha20-poly1305)
- `request.key` — Hex-encoded encryption key
- `request.nonce` — Hex-encoded nonce
- `request.plaintext` — Hex-encoded plaintext
- `request.aad` — Optional hex-encoded additional authenticated data

### Output
- `ciphertext` — Hex-encoded ciphertext
- `tag` — Hex-encoded authentication tag
- `backend` — "skill:crypto-aead.encrypt"

## decrypt

### Input
- `request.algorithm` — AEAD algorithm (aes-256-gcm, chacha20-poly1305)
- `request.key` — Hex-encoded encryption key
- `request.nonce` — Hex-encoded nonce
- `request.ciphertext` — Hex-encoded ciphertext
- `request.tag` — Hex-encoded authentication tag
- `request.aad` — Optional hex-encoded additional authenticated data

### Output
- `plaintext` — Hex-encoded plaintext
- `backend` — "skill:crypto-aead.decrypt"
