// Stub: VRF (Verifiable Random Function) is not available in node:crypto.
// Requires EC-VRF per RFC 9381 or a curve-specific implementation.

export function run(input) {
  const { privateKey, alpha } = input?.request ?? {};
  if (!privateKey) throw new Error("missing request.privateKey");
  if (!alpha) throw new Error("missing request.alpha (input to VRF)");
  return {
    error: "native binding required",
    algorithm: "ecvrf-ed25519-sha512-elligator2",
    nativeApi: {
      function: "ecvrf_prove",
      params: ["private_key: 32 bytes", "alpha: arbitrary bytes"],
      returns: "{ proof: 80 bytes, beta: 64 bytes (VRF output) }",
    },
    backend: "skill:crypto-vrf.prove",
  };
}
