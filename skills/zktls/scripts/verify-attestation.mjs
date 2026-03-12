/**
 * Verify a zk-TLS attestation produced by the TLSNotary prover.
 *
 * Requires the native module built from native/. If the native module is not
 * available, returns a structured error indicating the native binding is required.
 *
 * @param {object} input
 * @param {object} input.request
 * @param {string} input.request.attestation        — serialized attestation JSON
 * @param {string} [input.request.expectedServerName] — optional hostname to validate
 * @returns {Promise<object>} VerifyResult with validity, server name, revealed transcript
 */
export async function run(input) {
  const request = input?.request;
  if (!request) throw new Error("missing input.request");
  if (!request.attestation) throw new Error("missing request.attestation");

  let native;
  try {
    native = await import("../../../native/openskills-zktls.node");
  } catch {
    return {
      error: "native binding required — build native/ with: cd native && npm run build",
      backend: "skill:zktls.verify-attestation",
    };
  }

  const result = await native.verify({
    attestation: request.attestation,
    expectedServerName: request.expectedServerName || null,
  });

  return {
    valid: result.valid,
    serverName: result.serverName,
    revealedSent: result.revealedSent || null,
    revealedRecv: result.revealedRecv || null,
    attestationSha256: result.attestationSha256,
    backend: "skill:zktls.verify-attestation",
  };
}
