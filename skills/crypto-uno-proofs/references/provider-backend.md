# crypto-uno-proofs — verify backend

## verify

### Input
- `request.proofType` — Proof type (shield, ct_validity, commitment_eq, balance)
- `request.proof` — Hex-encoded proof
- `request.params` — Object with proof-type-specific parameters

### Output
- `valid` — Boolean verification result
- `proofType` — Proof type verified
- `backend` — "skill:crypto-uno-proofs.verify"
