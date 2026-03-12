import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { run } from "../skills/zktls/scripts/bundle.mjs";

function sha256(str) {
  return `0x${createHash("sha256").update(str).digest("hex")}`;
}

const BASE_REQUEST = {
  source_url: "https://news.example.com/story",
  publisher_hint: "Example News",
  headline_hint: "Breaking Story",
};

const BASE_CAPTURE = {
  canonicalUrl: "https://news.example.com/story",
  httpStatus: 200,
  contentType: "text/html",
  articleSha256: `0x${"ab".repeat(32)}`,
  articleText: "Article body text",
  headline: "Breaking Story",
  publisher: "Example News",
};

describe("zktls bundle", () => {
  it("produces a valid bundle with SHA-256 digest", () => {
    const result = run({
      request: BASE_REQUEST,
      capture: BASE_CAPTURE,
      fetchedAt: 1700000000,
    });
    expect(result.format).toBe("zktls_bundle_v1");
    expect(result.bundleSha256).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.backend).toBe("skill:zktls.bundle");
    expect(result.bundle.version).toBe(1);
    expect(result.bundle.source_url).toBe("https://news.example.com/story");
    expect(result.bundle.article_sha256).toBe(`0x${"ab".repeat(32)}`);
    expect(result.bundle.fetched_at).toBe(1700000000);
  });

  it("is deterministic — same inputs produce same hash", () => {
    const a = run({ request: BASE_REQUEST, capture: BASE_CAPTURE, fetchedAt: 1700000000 });
    const b = run({ request: BASE_REQUEST, capture: BASE_CAPTURE, fetchedAt: 1700000000 });
    expect(a.bundleSha256).toBe(b.bundleSha256);
    expect(JSON.stringify(a.bundle)).toBe(JSON.stringify(b.bundle));
  });

  it("bundleSha256 matches SHA-256 of JSON.stringify(bundle)", () => {
    const result = run({ request: BASE_REQUEST, capture: BASE_CAPTURE, fetchedAt: 1700000000 });
    const expected = sha256(JSON.stringify(result.bundle));
    expect(result.bundleSha256).toBe(expected);
  });

  it("different fetchedAt produces different hash", () => {
    const a = run({ request: BASE_REQUEST, capture: BASE_CAPTURE, fetchedAt: 1700000000 });
    const b = run({ request: BASE_REQUEST, capture: BASE_CAPTURE, fetchedAt: 1700000001 });
    expect(a.bundleSha256).not.toBe(b.bundleSha256);
  });

  it("fills optional fields with null", () => {
    const result = run({
      request: { source_url: "https://example.com" },
      capture: { articleSha256: `0x${"cc".repeat(32)}` },
      fetchedAt: 1700000000,
    });
    expect(result.bundle.publisher_hint).toBeNull();
    expect(result.bundle.headline_hint).toBeNull();
    expect(result.bundle.source_policy_id).toBeNull();
    expect(result.bundle.headline).toBeNull();
    expect(result.bundle.publisher).toBeNull();
    expect(result.bundle.article_preview).toBeNull();
  });

  it("uses canonical_url from capture, falls back to source_url", () => {
    const withCanonical = run({
      request: { source_url: "https://a.com" },
      capture: { canonicalUrl: "https://b.com", articleSha256: "0x" + "aa".repeat(32) },
      fetchedAt: 1,
    });
    expect(withCanonical.bundle.canonical_url).toBe("https://b.com");

    const withoutCanonical = run({
      request: { source_url: "https://a.com" },
      capture: { articleSha256: "0x" + "aa".repeat(32) },
      fetchedAt: 1,
    });
    expect(withoutCanonical.bundle.canonical_url).toBe("https://a.com");
  });

  it("includes source_policy_id when provided", () => {
    const result = run({
      request: { source_url: "https://example.com", source_policy_id: "major-news-v1" },
      capture: { articleSha256: `0x${"dd".repeat(32)}` },
      fetchedAt: 1700000000,
    });
    expect(result.bundle.source_policy_id).toBe("major-news-v1");
  });

  it("throws on missing request", () => {
    expect(() => run({})).toThrow("missing input.request");
  });

  it("throws on missing capture", () => {
    expect(() => run({ request: BASE_REQUEST })).toThrow("missing input.capture");
  });

  it("throws on missing source_url", () => {
    expect(() => run({ request: {}, capture: BASE_CAPTURE })).toThrow("missing request.source_url");
  });

  it("throws on missing articleSha256", () => {
    expect(() =>
      run({ request: BASE_REQUEST, capture: { httpStatus: 200 } }),
    ).toThrow("missing capture.articleSha256");
  });
});
