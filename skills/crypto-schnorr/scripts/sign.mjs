// Stub: TOS-variant Schnorr over ristretto255 is not available in node:crypto.
// Native implementation requires: ristretto255 group operations, TOS challenge
// derivation, and deterministic nonce generation per the TOS Schnorr spec.

export function run(input) {
  const { privateKey, message } = input?.request ?? {};
  if (!privateKey) throw new Error("missing request.privateKey");
  if (!message) throw new Error("missing request.message");
  return {
    error: "native binding required",
    algorithm: "tos-schnorr-ristretto255",
    nativeApi: {
      function: "tos_schnorr_sign",
      params: ["private_key: 32 bytes", "message: arbitrary bytes"],
      returns: "signature: 64 bytes (R || s)",
    },
    backend: "skill:crypto-schnorr.sign",
  };
}
