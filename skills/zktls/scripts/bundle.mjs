import { createHash } from "node:crypto";

/**
 * Build a deterministic evidence bundle from bounded capture fields.
 *
 * @param {object} input
 * @param {object} input.request  — { source_url, publisher_hint?, headline_hint?, source_policy_id? }
 * @param {object} input.capture  — { canonicalUrl, httpStatus, contentType, articleSha256, articleText?, headline?, publisher? }
 * @param {number} [input.fetchedAt] — epoch seconds (defaults to now)
 * @returns {{ format: string, bundle: object, bundleSha256: string, backend: string }}
 */
export function run(input) {
  const request = input?.request;
  if (!request) throw new Error("missing input.request");

  const capture = input?.capture;
  if (!capture) throw new Error("missing input.capture");

  if (!request.source_url) throw new Error("missing request.source_url");
  if (!capture.articleSha256) throw new Error("missing capture.articleSha256");

  const fetchedAt = Number(input.fetchedAt || Math.floor(Date.now() / 1000));

  const bundle = {
    version: 1,
    backend: "skill:zktls.bundle",
    fetched_at: fetchedAt,
    source_url: request.source_url,
    canonical_url: capture.canonicalUrl || request.source_url,
    source_policy_id: request.source_policy_id || null,
    publisher_hint: request.publisher_hint || null,
    headline_hint: request.headline_hint || null,
    http_status: capture.httpStatus,
    content_type: capture.contentType,
    article_sha256: capture.articleSha256,
    headline: capture.headline || null,
    publisher: capture.publisher || null,
    article_preview: capture.articleText || null,
  };

  const bundleSha256 = `0x${createHash("sha256").update(JSON.stringify(bundle)).digest("hex")}`;

  return {
    format: "zktls_bundle_v1",
    bundle,
    bundleSha256,
    backend: "skill:zktls.bundle",
  };
}
