---
name: crypto-rangeproofs
description: "Bulletproofs range proof verification with Merlin transcript Fiat-Shamir transform. Use when: verifying confidential transaction amounts, validating committed values are in range, privacy-preserving balance checks. NOT for: generating range proofs (prover-side), general-purpose ZK circuits, or non-Bulletproofs proof systems."
license: MIT
metadata: { "openfox": { "requires": { "bins": ["node"] }, "provider-backends": { "verify": { "entry": "scripts/verify.mjs", "description": "Verify Bulletproofs range proofs" } } } }
---

This skill implements Bulletproofs range proof verification, which proves that a committed value lies within a specified range without revealing the value itself. Bulletproofs are logarithmic-size range proofs (O(log n) in the bit-length of the range) and are used in confidential transaction systems to ensure that transaction amounts are non-negative without disclosing them. The Fiat-Shamir transform uses Merlin transcripts for deterministic, domain-separated challenge derivation.

The verify backend accepts one or more Pedersen commitments (up to 8 in a single batch), the corresponding range proofs, and the bit-length of the range (variable, 64 to 256 bits). Batch verification of multiple proofs is more efficient than individual verification due to amortized multi-scalar multiplication. The proof format follows the standard Bulletproofs construction with inner product arguments. Both reference C and AVX-512 optimized implementations are available, selected automatically based on platform capabilities.

Header references: `lib/include/at/crypto/at_rangeproofs.h`, `at_merlin.h`, `at_rangeproofs_transcript.h`. The Merlin transcript framework provides structured Fiat-Shamir transforms with domain separation, preventing cross-protocol attacks. Precomputed generator tables accelerate the multi-scalar multiplication that dominates verification time. When verifying in batch, all proofs must use the same bit-length parameter. The generators (G and H vectors) are derived deterministically and must match between prover and verifier. Invalid proofs will be rejected — the verification is all-or-nothing with no partial failure mode.
