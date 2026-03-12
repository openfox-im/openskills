import { createHash } from "node:crypto";

/**
 * Verify M-of-N consensus across multiple agent attestation results.
 *
 * Checks that at least M out of N attestation results agree on verdict,
 * server_name, and optionally article content hash. Pure JS, no native
 * module required.
 *
 * @param {object} input
 * @param {object} input.request
 * @param {number} input.request.m                — minimum agreeing agents
 * @param {number} input.request.n                — total agents
 * @param {object[]} input.request.agentResults   — array of { verdict, serverName?, articleSha256?, attestationSha256? }
 * @param {string}  [input.request.expectedServerName]  — required server hostname
 * @param {string}  [input.request.expectedArticleSha256] — required content hash
 * @returns {{ verdict, summary, metadata, verifierReceiptSha256, backend }}
 */
export function run(input) {
  const request = input?.request;
  if (!request) throw new Error("missing input.request");

  const m = Number(request.m);
  const n = Number(request.n);
  if (!Number.isFinite(m) || m < 1) throw new Error("request.m must be a positive integer");
  if (!Number.isFinite(n) || n < 1) throw new Error("request.n must be a positive integer");
  if (m > n) throw new Error("request.m cannot exceed request.n");

  const agentResults = request.agentResults;
  if (!Array.isArray(agentResults)) throw new Error("request.agentResults must be an array");
  if (agentResults.length !== n) {
    throw new Error(`request.agentResults length (${agentResults.length}) does not match request.n (${n})`);
  }

  const checks = [];

  // --- Verdict consensus ---
  const verdictCounts = {};
  for (const r of agentResults) {
    const v = String(r?.verdict || "unknown").toLowerCase();
    verdictCounts[v] = (verdictCounts[v] || 0) + 1;
  }
  const [topVerdict, topCount] = Object.entries(verdictCounts)
    .sort((a, b) => b[1] - a[1])[0] || ["unknown", 0];

  checks.push({
    label: "verdict_consensus",
    ok: topCount >= m,
    actual: `${topCount}/${n} agree on "${topVerdict}"`,
    expected: `≥${m}/${n} agreement`,
    details: verdictCounts,
  });

  // --- Server name consensus ---
  const serverNames = agentResults
    .map((r) => r?.serverName || r?.server_name)
    .filter(Boolean);

  if (serverNames.length > 0) {
    const nameCounts = {};
    for (const name of serverNames) {
      const lower = String(name).toLowerCase();
      nameCounts[lower] = (nameCounts[lower] || 0) + 1;
    }
    const [topName, nameCount] = Object.entries(nameCounts)
      .sort((a, b) => b[1] - a[1])[0] || ["", 0];

    checks.push({
      label: "server_name_consensus",
      ok: nameCount >= m,
      actual: `${nameCount}/${serverNames.length} agree on "${topName}"`,
      expected: `≥${m} agreement on server name`,
      details: nameCounts,
    });

    if (request.expectedServerName) {
      const expected = String(request.expectedServerName).toLowerCase();
      checks.push({
        label: "expected_server_name",
        ok: topName === expected && nameCount >= m,
        actual: topName,
        expected: request.expectedServerName,
      });
    }
  }

  // --- Article content hash consensus ---
  const articleHashes = agentResults
    .map((r) => r?.articleSha256 || r?.article_sha256)
    .filter(Boolean);

  if (articleHashes.length > 0) {
    const hashCounts = {};
    for (const hash of articleHashes) {
      const lower = String(hash).toLowerCase();
      hashCounts[lower] = (hashCounts[lower] || 0) + 1;
    }
    const [topHash, hashCount] = Object.entries(hashCounts)
      .sort((a, b) => b[1] - a[1])[0] || ["", 0];

    checks.push({
      label: "article_hash_consensus",
      ok: hashCount >= m,
      actual: `${hashCount}/${articleHashes.length} agree`,
      expected: `≥${m} agreement on article hash`,
    });

    if (request.expectedArticleSha256) {
      const expected = String(request.expectedArticleSha256).toLowerCase();
      checks.push({
        label: "expected_article_hash",
        ok: topHash === expected && hashCount >= m,
        actual: topHash,
        expected: request.expectedArticleSha256,
      });
    }
  }

  // --- Attestation uniqueness ---
  const attestationHashes = agentResults
    .map((r) => r?.attestationSha256 || r?.attestation_sha256)
    .filter(Boolean);

  if (attestationHashes.length > 1) {
    const unique = new Set(attestationHashes.map((h) => String(h).toLowerCase()));
    checks.push({
      label: "attestation_uniqueness",
      ok: unique.size === attestationHashes.length,
      actual: `${unique.size} unique of ${attestationHashes.length}`,
      expected: "all attestation hashes unique (independent proofs)",
    });
  }

  // --- Verdict ---
  let verdict = "inconclusive";
  if (checks.length > 0) {
    verdict = checks.every((c) => c.ok) ? "valid" : "invalid";
  }

  const failedCount = checks.filter((c) => !c.ok).length;
  const summary =
    verdict === "valid"
      ? `M-of-N consensus verified: ${topCount}/${n} agents agree (threshold ${m}/${n}). All ${checks.length} checks passed.`
      : verdict === "invalid"
        ? `Consensus verification failed: ${failedCount} of ${checks.length} checks failed. Top agreement: ${topCount}/${n} on "${topVerdict}" (need ${m}).`
        : "Insufficient data for consensus verification.";

  const metadata = {
    verifier_backend: "skill:proofverify.verify-consensus",
    verifier_class: "m_of_n_consensus_verification",
    consensus: `${topCount}/${n}`,
    threshold: `${m}/${n}`,
    threshold_met: topCount >= m,
    majority_verdict: topVerdict,
    verdict_distribution: verdictCounts,
    checks,
  };

  const verifierReceiptSha256 = `0x${createHash("sha256")
    .update(JSON.stringify({ m, n, verdict, checks, metadata }))
    .digest("hex")}`;

  return {
    verdict,
    verdictReason: verdict === "valid" ? "consensus_reached" : verdict === "invalid" ? "consensus_not_reached" : "no_checks_available",
    summary,
    metadata,
    verifierReceiptSha256,
    backend: "skill:proofverify.verify-consensus",
  };
}
