// Stub: ElGamal encryption over Curve25519 is not available in node:crypto.
// Requires: scalar multiplication, point encoding, and symmetric key derivation.

export function run(input) {
  const { publicKey, plaintext } = input?.request ?? {};
  if (!publicKey) throw new Error("missing request.publicKey");
  if (!plaintext) throw new Error("missing request.plaintext");
  return {
    error: "native binding required",
    algorithm: "x25519-elgamal",
    nativeApi: {
      function: "x25519_elgamal_encrypt",
      params: ["public_key: 32 bytes", "plaintext: arbitrary bytes"],
      returns: "{ ephemeralPub: 32 bytes, ciphertext: bytes }",
    },
    backend: "skill:crypto-x25519.encrypt",
  };
}
