// Stub: VRF verification is not available in node:crypto.

export function run(input) {
  const { publicKey, alpha, proof } = input?.request ?? {};
  if (!publicKey) throw new Error("missing request.publicKey");
  if (!alpha) throw new Error("missing request.alpha");
  if (!proof) throw new Error("missing request.proof");
  return {
    error: "native binding required",
    algorithm: "ecvrf-ed25519-sha512-elligator2",
    nativeApi: {
      function: "ecvrf_verify",
      params: ["public_key: 32 bytes", "alpha: arbitrary bytes", "proof: 80 bytes"],
      returns: "{ valid: boolean, beta: 64 bytes }",
    },
    backend: "skill:crypto-vrf.verify",
  };
}
