# crypto-rangeproofs — verify backend

## verify

### Input
- `request.proof` — Hex-encoded range proof
- `request.commitments` — Array of hex-encoded commitments
- `request.bitLengths` — Array of bit lengths for each commitment

### Output
- `valid` — Boolean verification result
- `backend` — "skill:crypto-rangeproofs.verify"
