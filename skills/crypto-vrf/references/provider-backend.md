# crypto-vrf — prove / verify backends

## prove

### Input
- `request.seed` — Hex-encoded 32-byte seed (64 hex chars)
- `request.input` — Hex-encoded input data

### Output
- `output` — Hex-encoded 32-byte VRF output (64 hex chars)
- `proof` — Hex-encoded 64-byte VRF proof (128 hex chars)
- `publicKey` — Hex-encoded public key
- `backend` — "skill:crypto-vrf.prove"

## verify

### Input
- `request.publicKey` — Hex-encoded public key
- `request.input` — Hex-encoded input data
- `request.output` — Hex-encoded VRF output
- `request.proof` — Hex-encoded VRF proof

### Output
- `valid` — Boolean verification result
- `backend` — "skill:crypto-vrf.verify"
