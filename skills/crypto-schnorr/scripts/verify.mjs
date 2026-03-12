// Stub: TOS-variant Schnorr over ristretto255 is not available in node:crypto.

export function run(input) {
  const { publicKey, message, signature } = input?.request ?? {};
  if (!publicKey) throw new Error("missing request.publicKey");
  if (!message) throw new Error("missing request.message");
  if (!signature) throw new Error("missing request.signature");
  return {
    error: "native binding required",
    algorithm: "tos-schnorr-ristretto255",
    nativeApi: {
      function: "tos_schnorr_verify",
      params: ["public_key: 32 bytes", "message: arbitrary bytes", "signature: 64 bytes"],
      returns: "valid: boolean",
    },
    backend: "skill:crypto-schnorr.verify",
  };
}
