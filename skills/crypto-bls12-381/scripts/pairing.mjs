// Stub: BLS12-381 pairing operations are not available in node:crypto.
// Requires: G1/G2 point arithmetic, Miller loop, final exponentiation.

export function run(input) {
  const { g1Point, g2Point } = input?.request ?? {};
  if (!g1Point) throw new Error("missing request.g1Point");
  if (!g2Point) throw new Error("missing request.g2Point");
  return {
    error: "native binding required",
    algorithm: "bls12-381-pairing",
    nativeApi: {
      function: "bls12_381_pairing",
      params: ["g1_point: 48 bytes (compressed)", "g2_point: 96 bytes (compressed)"],
      returns: "{ gt: 576 bytes (Fp12 element) }",
    },
    backend: "skill:crypto-bls12-381.pairing",
  };
}
