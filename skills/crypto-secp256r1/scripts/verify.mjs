import { createVerify, createPublicKey } from "node:crypto";

export function run(input) {
  const { publicKey, message, signature } = input?.request ?? {};
  if (!publicKey) throw new Error("missing request.publicKey");
  if (!message) throw new Error("missing request.message");
  if (!signature) throw new Error("missing request.signature");
  const pubBuf = Buffer.from(publicKey.replace(/^0x/, ""), "hex");
  const msgBuf = Buffer.from(message.replace(/^0x/, ""), "hex");
  const sigBuf = Buffer.from(signature.replace(/^0x/, ""), "hex");
  if (sigBuf.length !== 64) throw new Error("signature must be 64 bytes (r || s)");
  const uncompressed = pubBuf.length === 65 ? pubBuf : Buffer.concat([Buffer.from([0x04]), pubBuf]);
  const spki = Buffer.concat([
    Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"),
    uncompressed,
  ]);
  const keyObj = createPublicKey({ key: spki, format: "der", type: "spki" });
  const verifier = createVerify("SHA256");
  verifier.update(msgBuf);
  verifier.end();
  const valid = verifier.verify({ key: keyObj, dsaEncoding: "ieee-p1363" }, sigBuf);
  return { valid, backend: "skill:crypto-secp256r1.verify" };
}
