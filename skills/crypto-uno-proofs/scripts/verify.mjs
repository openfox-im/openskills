// Stub: UNO proof verification is not available in node:crypto.
// Requires: UNO-specific circuit verification and commitment scheme.

export function run(input) {
  const { proof, publicInputs } = input?.request ?? {};
  if (!proof) throw new Error("missing request.proof");
  if (!publicInputs) throw new Error("missing request.publicInputs");
  return {
    error: "native binding required",
    algorithm: "uno-proof-system",
    nativeApi: {
      function: "uno_proof_verify",
      params: ["proof: variable bytes", "public_inputs: array of field elements"],
      returns: "{ valid: boolean }",
    },
    backend: "skill:crypto-uno-proofs.verify",
  };
}
