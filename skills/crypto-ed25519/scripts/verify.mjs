import { verify, createPublicKey } from "node:crypto";

export function run(input) {
  const { publicKey, message, signature } = input?.request ?? {};
  if (!publicKey) throw new Error("missing request.publicKey");
  if (!message) throw new Error("missing request.message");
  if (!signature) throw new Error("missing request.signature");
  const pubRaw = Buffer.from(publicKey.replace(/^0x/, ""), "hex");
  if (pubRaw.length !== 32) throw new Error("publicKey must be 32 bytes");
  const msgBuf = Buffer.from(message.replace(/^0x/, ""), "hex");
  const sigBuf = Buffer.from(signature.replace(/^0x/, ""), "hex");
  if (sigBuf.length !== 64) throw new Error("signature must be 64 bytes");
  const spki = Buffer.concat([
    Buffer.from("302a300506032b6570032100", "hex"),
    pubRaw,
  ]);
  const keyObj = createPublicKey({ key: spki, format: "der", type: "spki" });
  const valid = verify(null, msgBuf, keyObj, sigBuf);
  return { valid, backend: "skill:crypto-ed25519.verify" };
}
