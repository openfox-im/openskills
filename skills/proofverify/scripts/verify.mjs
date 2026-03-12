import { createHash } from "node:crypto";

const SUBJECT_HASH_KEYS = [
  "article_sha256",
  "subject_sha256",
  "content_sha256",
  "body_sha256",
];

const BUNDLE_HASH_KEYS = [
  "zktls_bundle_sha256",
  "proof_bundle_sha256",
  "bundle_sha256",
];

function sha256Hex(data) {
  return `0x${createHash("sha256").update(data).digest("hex")}`;
}

function extractHash(obj, keys) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
  for (const key of keys) {
    const val = obj[key];
    if (typeof val === "string" && /^0x[0-9a-f]{64}$/i.test(val)) {
      return val.toLowerCase();
    }
  }
  for (const nested of ["metadata", "bundle", "result"]) {
    if (obj[nested]) {
      const found = extractHash(obj[nested], keys);
      if (found) return found;
    }
  }
  return null;
}

/**
 * Verify bounded bundle and subject hash relationships.
 *
 * @param {object} input
 * @param {object} input.request
 * @param {string} [input.request.subject_sha256]       — expected subject hash
 * @param {string} [input.request.subject_body]          — raw subject content (will be hashed)
 * @param {object} [input.request.proof_bundle]          — bundle JSON object
 * @param {string} [input.request.proof_bundle_sha256]   — expected bundle hash
 * @returns {{ verdict, summary, metadata, verifierReceiptSha256, backend }}
 */
export function run(input) {
  const request = input?.request;
  if (!request) throw new Error("missing input.request");

  const checks = [];
  const metadata = { verifier_backend: "skill:proofverify.verify" };

  // --- subject ---
  let subjectSha = null;
  if (request.subject_body != null) {
    const body =
      typeof request.subject_body === "string"
        ? request.subject_body
        : JSON.stringify(request.subject_body);
    subjectSha = sha256Hex(body);
    metadata.subject = { sha256: subjectSha };

    if (request.subject_sha256) {
      checks.push({
        label: "subject_sha256",
        ok: subjectSha.toLowerCase() === String(request.subject_sha256).toLowerCase(),
        actual: subjectSha,
        expected: request.subject_sha256,
      });
    }
  } else if (request.subject_sha256) {
    subjectSha = String(request.subject_sha256).toLowerCase();
    metadata.subject = { declared_sha256: request.subject_sha256 };
  }

  // --- bundle ---
  let bundleBodySha = null;
  let referencedSubjectSha = null;

  if (request.proof_bundle != null) {
    const bundleStr =
      typeof request.proof_bundle === "string"
        ? request.proof_bundle
        : JSON.stringify(request.proof_bundle);
    bundleBodySha = sha256Hex(bundleStr);

    const parsed =
      typeof request.proof_bundle === "object"
        ? request.proof_bundle
        : (() => {
            try { return JSON.parse(bundleStr); } catch { return null; }
          })();

    referencedSubjectSha = parsed ? extractHash(parsed, SUBJECT_HASH_KEYS) : null;
    const referencedBundleSha = parsed ? extractHash(parsed, BUNDLE_HASH_KEYS) : null;

    metadata.bundle = {
      sha256: bundleBodySha,
      declared_bundle_sha256: referencedBundleSha || null,
      referenced_subject_sha256: referencedSubjectSha || null,
    };

    if (request.proof_bundle_sha256) {
      const actual = referencedBundleSha || bundleBodySha;
      checks.push({
        label: "proof_bundle_sha256",
        ok: actual.toLowerCase() === String(request.proof_bundle_sha256).toLowerCase(),
        actual,
        expected: request.proof_bundle_sha256,
      });
    }

    if (subjectSha && referencedSubjectSha) {
      checks.push({
        label: "bundle_subject_sha256",
        ok: referencedSubjectSha === subjectSha,
        actual: referencedSubjectSha,
        expected: subjectSha,
      });
    }
  } else if (request.proof_bundle_sha256) {
    metadata.bundle = { declared_sha256: request.proof_bundle_sha256 };
  }

  // --- verdict ---
  const verifierClass =
    request.proof_bundle != null || request.proof_bundle_sha256
      ? "bundle_integrity_verification"
      : "structural_verification";
  metadata.verifier_class = verifierClass;

  let verdict = "inconclusive";
  if (checks.length > 0) {
    verdict = checks.every((c) => c.ok) ? "valid" : "invalid";
  }

  const invalidCount = checks.filter((c) => !c.ok).length;
  const summary =
    verdict === "valid"
      ? `Verified ${checks.length} proof check${checks.length === 1 ? "" : "s"} successfully.`
      : verdict === "invalid"
        ? `Verification failed for ${invalidCount} check${invalidCount === 1 ? "" : "s"}.`
        : "No comparable hashes were available, so the result is inconclusive.";

  metadata.checks = checks;

  const verifierReceiptSha256 = sha256Hex(
    JSON.stringify({ request, verdict, checks, metadata })
  );

  return {
    verdict,
    summary,
    metadata,
    verifierReceiptSha256,
    backend: "skill:proofverify.verify",
  };
}
