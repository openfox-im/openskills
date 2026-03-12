---
name: crypto-uno-proofs
description: "UNO confidential transaction proofs — shield commitment, ciphertext validity, commitment equality, and balance proofs. Use when: verifying TOS confidential transfers, validating shield/unshield operations, checking commitment equality across accounts. NOT for: non-TOS proof systems, generating proofs (prover-side), or general ZK circuits."
license: MIT
requires:
  bins:
    - node
provider-backends:
  verify:
    entry: scripts/verify.mjs
    description: "Verify UNO zero-knowledge proofs"
---

This skill verifies UNO zero-knowledge proofs used in TOS confidential transactions. Four proof types are supported: ShieldCommitmentProof (96 bytes) proves that a Pedersen commitment correctly encodes a publicly known value; CiphertextValidityProof proves that an ElGamal ciphertext encrypts the same value as a Pedersen commitment, with two sub-variants — T0 (128 bytes) for standard transfers and T1 (160 bytes) for extended transfers; CommitmentEqProof (192 bytes) proves that two commitments with different blinding factors encode the same value; and BalanceProof proves that the sum of input commitments equals the sum of output commitments (conservation of value).

The verify backend accepts a proof type, the serialized proof bytes, and the associated public inputs (commitments, ciphertexts, public keys) needed for verification. All proofs operate on the Ristretto255 group and use domain separators matching the TOS Rust reference implementation, ensuring cross-implementation compatibility. For human-readable serialization, proofs can be encoded in Bech32 format with the "proof" prefix, enabling copy-paste-safe representation.

Header references: `lib/include/at/crypto/at_uno_proofs.h`, `at_human_readable_proof.h`. These proofs are the core of TOS confidential transactions — every shielded transfer requires at least a CiphertextValidityProof and a BalanceProof. The domain separators are critical for security and must exactly match the TOS specification. Proof verification is constant-time with respect to the secret witness. When processing proofs from untrusted sources, always validate the proof byte length before attempting deserialization to prevent out-of-bounds reads.
