// Stub: BN254 (alt_bn128) pairing operations are not available in node:crypto.
// Requires: G1/G2 arithmetic over BN254, optimal ate pairing.

export function run(input) {
  const { g1Point, g2Point } = input?.request ?? {};
  if (!g1Point) throw new Error("missing request.g1Point");
  if (!g2Point) throw new Error("missing request.g2Point");
  return {
    error: "native binding required",
    algorithm: "bn254-pairing",
    nativeApi: {
      function: "bn254_pairing",
      params: ["g1_point: 64 bytes (uncompressed x,y)", "g2_point: 128 bytes (uncompressed)"],
      returns: "{ gt: 384 bytes (Fp12 element) }",
    },
    backend: "skill:crypto-bn254.pairing",
  };
}
