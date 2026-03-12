# zktls — Provider Backend

## bundle

Packages HTTP capture results into a deterministic, hashable evidence bundle.

**Entry:** `scripts/bundle.mjs`

### Pipeline stage

1. Caller fetches a bounded public URL and produces a capture result
2. **This backend** wraps the capture into a versioned bundle with canonical field order
3. SHA-256 of `JSON.stringify(bundle)` provides the bundle digest
4. The bundle + digest can be passed to `proofverify.verify` for validation

### Determinism guarantee

Same `(request, capture, fetchedAt)` inputs always produce the same `bundleSha256`. This enables independent verification — any party can recompute the hash from the bundle JSON.
