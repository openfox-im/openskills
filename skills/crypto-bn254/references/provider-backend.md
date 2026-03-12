# crypto-bn254 — pairing backend

## pairing

### Input
- `request.operation` — Operation type (g1_add, g2_add, g1_mul, g2_mul, pairing)
- `request.points` — Array of hex-encoded curve points
- `request.scalar` — Optional hex-encoded scalar for multiplication operations

### Output
- `result` — Hex-encoded result
- `operation` — Operation performed
- `backend` — "skill:crypto-bn254.pairing"
