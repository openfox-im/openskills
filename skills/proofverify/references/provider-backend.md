# proofverify — Provider Backend

## verify

Validates evidence bundle integrity by comparing SHA-256 hashes.

**Entry:** `scripts/verify.mjs`

### Pipeline stage

1. `zktls.bundle` produces a deterministic bundle + bundleSha256
2. **This backend** accepts the bundle and/or subject data
3. Performs up to 3 hash checks:
   - `subject_sha256` — does the provided subject body hash match the declared hash?
   - `proof_bundle_sha256` — does the bundle hash match the declared bundle hash?
   - `bundle_subject_sha256` — does the bundle's internal article_sha256 match the subject hash?
4. Returns verdict (valid/invalid/inconclusive) + detailed check results

### Verdicts

- **valid** — all checks pass
- **invalid** — at least one check fails
- **inconclusive** — no comparable hashes available (e.g., only declared hashes, no content to verify)

### Offline operation

Unlike the OpenFox built-in version, this skill does not perform HTTP fetches. All data must be provided in the request. This makes it suitable for offline verification, testing, and deterministic replay.
