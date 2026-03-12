import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { run as bundle } from "../skills/zktls/scripts/bundle.mjs";
import { run as verify } from "../skills/proofverify/scripts/verify.mjs";

function sha256(str) {
  return `0x${createHash("sha256").update(str).digest("hex")}`;
}

describe("proofverify", () => {
  // Create a bundle to use in tests
  const bundleResult = bundle({
    request: { source_url: "https://example.com/article" },
    capture: {
      canonicalUrl: "https://example.com/article",
      httpStatus: 200,
      contentType: "text/html",
      articleSha256: sha256("article content"),
    },
    fetchedAt: 1700000000,
  });

  describe("end-to-end with zktls bundle", () => {
    it("valid — bundle hash matches", () => {
      const result = verify({
        request: {
          proof_bundle: bundleResult.bundle,
          proof_bundle_sha256: bundleResult.bundleSha256,
        },
      });
      expect(result.verdict).toBe("valid");
      expect(result.backend).toBe("skill:proofverify.verify");
      expect(result.metadata.verifier_class).toBe("bundle_integrity_verification");
      expect(result.verifierReceiptSha256).toMatch(/^0x[0-9a-f]{64}$/);
    });

    it("valid — subject + bundle cross-reference", () => {
      const subjectHash = sha256("article content");
      const result = verify({
        request: {
          subject_sha256: subjectHash,
          proof_bundle: bundleResult.bundle,
        },
      });
      expect(result.verdict).toBe("valid");
      expect(result.metadata.checks).toHaveLength(1);
      expect(result.metadata.checks[0].label).toBe("bundle_subject_sha256");
    });

    it("valid — subject body hash matches declared", () => {
      const result = verify({
        request: {
          subject_body: "article content",
          subject_sha256: sha256("article content"),
        },
      });
      expect(result.verdict).toBe("valid");
      expect(result.metadata.checks[0].label).toBe("subject_sha256");
    });
  });

  describe("invalid cases", () => {
    it("invalid — bundle hash mismatch", () => {
      const result = verify({
        request: {
          proof_bundle: bundleResult.bundle,
          proof_bundle_sha256: "0x" + "00".repeat(32),
        },
      });
      expect(result.verdict).toBe("invalid");
      expect(result.summary).toContain("failed");
    });

    it("invalid — subject hash mismatch", () => {
      const result = verify({
        request: {
          subject_body: "wrong content",
          subject_sha256: sha256("original content"),
        },
      });
      expect(result.verdict).toBe("invalid");
    });

    it("invalid — bundle references wrong subject", () => {
      const result = verify({
        request: {
          subject_sha256: "0x" + "ff".repeat(32),
          proof_bundle: bundleResult.bundle,
        },
      });
      expect(result.verdict).toBe("invalid");
      expect(result.metadata.checks[0].label).toBe("bundle_subject_sha256");
    });
  });

  describe("inconclusive cases", () => {
    it("inconclusive — only declared subject hash, no body", () => {
      const result = verify({
        request: {
          subject_sha256: sha256("something"),
        },
      });
      expect(result.verdict).toBe("inconclusive");
      expect(result.metadata.verifier_class).toBe("structural_verification");
      expect(result.summary).toContain("inconclusive");
    });

    it("inconclusive — only declared bundle hash, no bundle", () => {
      const result = verify({
        request: {
          proof_bundle_sha256: "0x" + "aa".repeat(32),
        },
      });
      expect(result.verdict).toBe("inconclusive");
    });
  });

  describe("receipt determinism", () => {
    it("same inputs produce same receipt hash", () => {
      const a = verify({ request: { subject_body: "test", subject_sha256: sha256("test") } });
      const b = verify({ request: { subject_body: "test", subject_sha256: sha256("test") } });
      expect(a.verifierReceiptSha256).toBe(b.verifierReceiptSha256);
    });
  });

  describe("bundle as string", () => {
    it("accepts proof_bundle as JSON string", () => {
      const result = verify({
        request: {
          proof_bundle: JSON.stringify(bundleResult.bundle),
          proof_bundle_sha256: bundleResult.bundleSha256,
        },
      });
      expect(result.verdict).toBe("valid");
    });
  });

  describe("error handling", () => {
    it("throws on missing request", () => {
      expect(() => verify({})).toThrow("missing input.request");
    });
  });
});
