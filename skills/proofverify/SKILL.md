---
name: proofverify
description: "Proof verification for zk-TLS evidence bundles — three backends: hash integrity (verify), TLSNotary attestation validation (verify-attestations), and M-of-N consensus checking (verify-consensus). Use when: verifying zktls bundle receipts, validating TLSNotary session proofs, checking M-of-N agent consensus. NOT for: ZK circuit verification (use crypto-uno-proofs/crypto-rangeproofs), signature verification (use ed25519/secp256k1), or bundle creation (use zktls)."
license: MIT
requires:
  bins:
    - node
provider-backends:
  verify:
    entry: scripts/verify.mjs
    description: "Verify bounded bundle and subject hash relationships (pure JS)"
  verify-attestations:
    entry: scripts/verify-attestations.mjs
    description: "Validate TLSNotary attestation cryptographic structure within a bundle (native binding required)"
  verify-consensus:
    entry: scripts/verify-consensus.mjs
    description: "Check M-of-N consensus across multiple agent attestation results (pure JS)"
---

Three-backend verification pipeline for zk-TLS evidence:

**verify** — Pure JS hash comparison. Given a subject and proof bundle, compares SHA-256 hashes. Returns valid/invalid/inconclusive. Deterministic, no native dependency.

**verify-attestations** — Validates each TLSNotary attestation in a bundle via the native module (`openskills-zktls.node`). Checks attestation structure, server_name consistency, and optional whitelist. Requires: `cd native && npm run build`.

**verify-consensus** — Pure JS M-of-N consensus check. Given N agent results, verifies at least M agree on verdict, server_name, and article content hash. Checks attestation uniqueness (independent proofs).

Load `references/verify-contract.json` for the hash verify I/O contract.
Load `references/verify-attestations-contract.json` for the attestation verify I/O contract.
Load `references/verify-consensus-contract.json` for the consensus verify I/O contract.
