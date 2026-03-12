/**
 * zk-TLS proof generation via TLSNotary native module.
 *
 * Requires the native module built from native/. If the native module is not
 * available, returns a structured error indicating the native binding is required.
 *
 * @param {object} input
 * @param {object} input.request
 * @param {string} input.request.serverHost     — target HTTPS hostname
 * @param {number} [input.request.serverPort]   — target port (default 443)
 * @param {string} input.request.notaryHost     — notary/verifier address
 * @param {number} [input.request.notaryPort]   — notary port (default 7047)
 * @param {string} input.request.method         — HTTP method (GET, POST, ...)
 * @param {string} input.request.path           — HTTP path
 * @param {Array}  [input.request.headers]      — [{ name, value }]
 * @param {string} [input.request.body]         — HTTP body
 * @param {number} [input.request.maxSentData]  — max bytes to send (default 4096)
 * @param {number} [input.request.maxRecvData]  — max bytes to receive (default 16384)
 * @param {Array}  [input.request.revealRanges] — [{ start, end }] byte ranges to reveal
 * @returns {Promise<object>} ProveResult with attestation, sha256, transcript info
 */
export async function run(input) {
  const request = input?.request;
  if (!request) throw new Error("missing input.request");
  if (!request.serverHost) throw new Error("missing request.serverHost");
  if (!request.notaryHost) throw new Error("missing request.notaryHost");
  if (!request.method) throw new Error("missing request.method");
  if (!request.path) throw new Error("missing request.path");

  let native;
  try {
    native = await import("../../../native/openskills-zktls.node");
  } catch {
    return {
      error: "native binding required — build native/ with: cd native && npm run build",
      backend: "skill:zktls.prove",
    };
  }

  const result = await native.prove({
    serverHost: request.serverHost,
    serverPort: request.serverPort ?? 443,
    notaryHost: request.notaryHost,
    notaryPort: request.notaryPort ?? 7047,
    request: {
      method: request.method,
      path: request.path,
      headers: request.headers || [],
      body: request.body || null,
    },
    maxSentData: request.maxSentData ?? 4096,
    maxRecvData: request.maxRecvData ?? 16384,
    revealRanges: request.revealRanges || null,
  });

  return {
    attestation: result.attestation,
    attestationSha256: result.attestationSha256,
    serverName: result.serverName,
    sentLen: result.sentLen,
    recvLen: result.recvLen,
    backend: "skill:zktls.prove",
  };
}
