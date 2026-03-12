import { sign, createPublicKey, createPrivateKey } from "node:crypto";

export function run(input) {
  const { privateKey, message } = input?.request ?? {};
  if (!privateKey) throw new Error("missing request.privateKey");
  if (!message) throw new Error("missing request.message");
  const rawKey = Buffer.from(privateKey.replace(/^0x/, ""), "hex");
  if (rawKey.length !== 32) throw new Error("privateKey must be 32 bytes (64 hex chars)");
  const msgBuf = Buffer.from(message.replace(/^0x/, ""), "hex");
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    rawKey,
  ]);
  const keyObj = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const sig = sign(null, msgBuf, keyObj);
  const pubObj = createPublicKey(keyObj);
  const spki = pubObj.export({ format: "der", type: "spki" });
  const pubRaw = spki.subarray(spki.length - 32);
  return {
    signature: "0x" + sig.toString("hex"),
    publicKey: "0x" + pubRaw.toString("hex"),
    backend: "skill:crypto-ed25519.sign",
  };
}
