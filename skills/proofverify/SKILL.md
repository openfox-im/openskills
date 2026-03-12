---
name: proofverify
description: "Deterministic proof verification — validates evidence bundle integrity by comparing SHA-256 hashes of subjects and bundles. Use when: verifying zktls bundle receipts, validating content integrity proofs, checking subject-bundle hash relationships. NOT for: ZK circuit verification (use crypto-uno-proofs/crypto-rangeproofs), signature verification (use ed25519/secp256k1), or bundle creation (use zktls)."
license: MIT
requires:
  bins:
    - node
provider-backends:
  verify:
    entry: scripts/verify.mjs
    description: "Verify bounded bundle and subject hash relationships"
---

This skill verifies the integrity of evidence bundles produced by the zktls skill. Given a subject (content) and a proof bundle, it performs SHA-256 hash comparisons to determine whether the bundle accurately represents the subject. The verification result is one of three verdicts: "valid" (all hash checks pass), "invalid" (at least one check fails), or "inconclusive" (insufficient data for comparison).

The verify backend accepts a request with optional fields: subject_sha256 (expected hash of the subject content), subject_body (raw subject content for hash computation), proof_bundle (the bundle JSON object), and proof_bundle_sha256 (expected hash of the bundle). It performs up to three checks: subject hash match, bundle hash match, and cross-reference (the bundle's internal article_sha256 matches the declared subject hash). Each check produces a labeled result with actual vs expected values.

This is the second stage of a two-stage evidence pipeline: zktls creates the bundle, and this skill validates it. The verification is purely deterministic — same inputs always produce the same verdict. A verifier receipt SHA-256 is returned for audit trails. Currently implements hash-based integrity verification; future versions will support TLSNotary session proof validation.
