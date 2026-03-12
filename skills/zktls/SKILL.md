---
name: zktls
description: "zk-TLS proof generation and verification via TLSNotary MPC-TLS protocol, plus deterministic evidence bundling. Use when: generating cryptographic proofs of HTTPS responses, creating verifiable evidence bundles, news article attestation, M-of-N LLM consensus over zk-TLS proofs. NOT for: general-purpose hashing (use crypto-hash), encryption, or non-TLS protocols."
license: MIT
requires:
  bins:
    - node
provider-backends:
  prove:
    entry: scripts/prove.mjs
    description: "Generate a zk-TLS attestation of an HTTPS session via TLSNotary (native binding required)"
  verify-attestation:
    entry: scripts/verify-attestation.mjs
    description: "Verify a zk-TLS attestation and extract revealed transcript (native binding required)"
  bundle:
    entry: scripts/bundle.mjs
    description: "Turn bounded capture fields into a stable bundle receipt with SHA-256 digest (pure JS)"
---

This skill provides three backends for zk-TLS operations:

**prove** (native) — Generates a TLSNotary zk-TLS attestation. The prover connects to both a notary/verifier and a target HTTPS server, executing the MPC-TLS protocol. The TLS session keys are split via 2-party computation so the notary can authenticate the transcript without seeing the plaintext. After the HTTP exchange, the prover selectively reveals chosen portions of the transcript and generates a cryptographic attestation. This is the core primitive for "SNARK over M-of-N small LLMs over zk-TLSes" — each LLM agent independently fetches from a news site and generates its own zk-TLS proof.

**verify-attestation** (native) — Verifies a TLSNotary attestation, checking the MPC transcript commitment, server certificate chain, and selective disclosure proofs. Returns the revealed portions of the sent/received transcript along with the server hostname. Use this to validate that a zk-TLS proof was genuinely produced from a TLS session with a specific server.

**bundle** (pure JS) — Deterministic evidence bundling for capture results. Packages HTTP response metadata (URL, status, content type, article hash) into a canonical JSON bundle with a SHA-256 digest. This is the lightweight complement to the cryptographic prove/verify backends — use it when you have already-captured content and need a hashable receipt for integrity tracking.

The native backends require building the Rust native module: `cd native && npm run build`. This compiles the TLSNotary `tlsn` crate via napi-rs into a Node.js native addon. Without the native module, prove and verify-attestation return structured error objects indicating the binding is required. The bundle backend works without native dependencies.
