// Stub: Bulletproofs / range proof verification is not available in node:crypto.
// Requires: Pedersen commitments, inner-product argument verification.

export function run(input) {
  const { commitment, proof, range } = input?.request ?? {};
  if (!commitment) throw new Error("missing request.commitment");
  if (!proof) throw new Error("missing request.proof");
  return {
    error: "native binding required",
    algorithm: "bulletproofs-range",
    nativeApi: {
      function: "bulletproofs_range_verify",
      params: ["commitment: 32 bytes (Pedersen)", "proof: variable bytes", "range?: { min, max }"],
      returns: "{ valid: boolean }",
    },
    backend: "skill:crypto-rangeproofs.verify",
  };
}
