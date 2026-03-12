import { createHash } from "node:crypto";
import { join } from "node:path";
import { homedir } from "node:os";
import { existsSync } from "node:fs";

/**
 * Verify TLSNotary attestations within a zktls evidence bundle.
 *
 * Validates each attestation's cryptographic structure via the native module,
 * checks server_name consistency across attestations, and optionally validates
 * against a server_name whitelist.
 *
 * @param {object} input
 * @param {object} input.request
 * @param {string[]} input.request.attestations        — serialized attestation JSONs
 * @param {string}   [input.request.expectedServerName] — hostname all attestations must match
 * @param {string[]} [input.request.serverNameWhitelist] — allowed hostnames (if set, server_name must be in list)
 * @param {string}   [input.request.expectedArticleSha256] — expected content hash across attestations
 * @returns {Promise<object>}
 */
export async function run(input) {
  const request = input?.request;
  if (!request) throw new Error("missing input.request");
  if (!request.attestations || !Array.isArray(request.attestations)) {
    throw new Error("missing or invalid request.attestations (expected array of serialized attestation strings)");
  }
  if (request.attestations.length === 0) {
    throw new Error("request.attestations must contain at least one attestation");
  }

  // Load native module
  let native;
  const nativePaths = [
    join(homedir(), ".agents", "skills", "openskills", "native", "openskills-zktls.node"),
    join(import.meta.url.replace("file://", ""), "..", "..", "..", "native", "openskills-zktls.node"),
  ];
  for (const p of nativePaths) {
    try {
      if (existsSync(p)) {
        native = await import(p);
        break;
      }
    } catch { /* try next */ }
  }
  // Fallback: try relative to this file
  if (!native) {
    try {
      native = await import("../../../native/openskills-zktls.node");
    } catch {
      return {
        error: "native binding required — build native/ with: cd native && npm run build",
        backend: "skill:proofverify.verify-attestations",
      };
    }
  }

  const results = [];
  const serverNames = new Set();
  const attestationHashes = [];
  const checks = [];

  // Verify each attestation
  for (let i = 0; i < request.attestations.length; i++) {
    const attestation = request.attestations[i];
    if (typeof attestation !== "string" || !attestation.trim()) {
      results.push({ index: i, valid: false, error: "empty or non-string attestation" });
      continue;
    }

    try {
      const result = await native.verify({ attestation });
      results.push({
        index: i,
        valid: result.valid,
        commitmentCount: result.commitmentCount,
        attestationSha256: result.attestationSha256,
        verificationLevel: result.verificationLevel,
        serverName: result.serverName || null,
      });
      if (result.valid) {
        attestationHashes.push(result.attestationSha256);
      }
      // Extract server_name from cryptographic verification
      if (result.serverName) {
        serverNames.add(result.serverName);
      }
    } catch (e) {
      results.push({
        index: i,
        valid: false,
        error: e instanceof Error ? e.message : String(e),
      });
    }
  }

  const validCount = results.filter((r) => r.valid).length;
  const totalCount = results.length;

  // Check: all attestations valid
  checks.push({
    label: "attestation_validity",
    ok: validCount === totalCount,
    actual: `${validCount}/${totalCount} valid`,
    expected: `${totalCount}/${totalCount} valid`,
  });

  // Check: server_name consistency
  if (serverNames.size > 0) {
    const consistent = serverNames.size === 1;
    const names = [...serverNames];
    checks.push({
      label: "server_name_consistency",
      ok: consistent,
      actual: consistent ? names[0] : names.join(", "),
      expected: "all attestations reference the same server",
    });

    // Check: expectedServerName
    if (request.expectedServerName) {
      const match = consistent && names[0] === request.expectedServerName;
      checks.push({
        label: "expected_server_name",
        ok: match,
        actual: names[0] || "(none)",
        expected: request.expectedServerName,
      });
    }

    // Check: whitelist
    if (request.serverNameWhitelist && Array.isArray(request.serverNameWhitelist)) {
      const whitelist = new Set(request.serverNameWhitelist.map((s) => String(s).toLowerCase()));
      const allAllowed = names.every((n) => whitelist.has(n.toLowerCase()));
      checks.push({
        label: "server_name_whitelist",
        ok: allAllowed,
        actual: names.join(", "),
        expected: `one of: ${[...whitelist].join(", ")}`,
      });
    }
  }

  // Check: attestation hash uniqueness (no duplicates)
  const uniqueHashes = new Set(attestationHashes);
  if (attestationHashes.length > 1) {
    checks.push({
      label: "attestation_uniqueness",
      ok: uniqueHashes.size === attestationHashes.length,
      actual: `${uniqueHashes.size} unique of ${attestationHashes.length}`,
      expected: `${attestationHashes.length} unique attestations`,
    });
  }

  // Verdict
  let verdict = "inconclusive";
  if (checks.length > 0) {
    verdict = checks.every((c) => c.ok) ? "valid" : "invalid";
  }

  const invalidCount = checks.filter((c) => !c.ok).length;
  const summary =
    verdict === "valid"
      ? `Verified ${totalCount} attestation${totalCount === 1 ? "" : "s"} — all ${checks.length} checks passed.`
      : verdict === "invalid"
        ? `Attestation verification failed: ${invalidCount} of ${checks.length} checks failed.`
        : "Insufficient data for attestation verification.";

  const metadata = {
    verifier_backend: "skill:proofverify.verify-attestations",
    verifier_class: "tlsnotary_attestation_verification",
    total_attestations: totalCount,
    valid_attestations: validCount,
    server_names: [...serverNames],
    attestation_hashes: attestationHashes,
    checks,
    results,
  };

  const verifierReceiptSha256 = `0x${createHash("sha256")
    .update(JSON.stringify({ request: { attestationCount: totalCount }, verdict, checks, metadata }))
    .digest("hex")}`;

  return {
    verdict,
    verdictReason: verdict === "valid" ? "all_attestations_valid" : verdict === "invalid" ? "attestation_check_failed" : "no_checks_available",
    summary,
    metadata,
    verifierReceiptSha256,
    backend: "skill:proofverify.verify-attestations",
  };
}
