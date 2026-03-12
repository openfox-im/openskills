import { createSign, createECDH, createPrivateKey } from "node:crypto";

export function run(input) {
  const { privateKey, message } = input?.request ?? {};
  if (!privateKey) throw new Error("missing request.privateKey");
  if (!message) throw new Error("missing request.message");
  const keyBuf = Buffer.from(privateKey.replace(/^0x/, ""), "hex");
  if (keyBuf.length !== 32) throw new Error("privateKey must be 32 bytes");
  const msgBuf = Buffer.from(message.replace(/^0x/, ""), "hex");
  if (msgBuf.length !== 32) throw new Error("message must be 32 bytes (pre-hashed)");
  const ecPriv = Buffer.concat([
    Buffer.from("30770201010420", "hex"), keyBuf,
    Buffer.from("a00a06082a8648ce3d030107a14403420004", "hex"),
    getUncompressedXY(keyBuf),
  ]);
  const keyObj = createPrivateKey({ key: ecPriv, format: "der", type: "sec1" });
  const signer = createSign("SHA256");
  signer.update(msgBuf);
  signer.end();
  const sig = signer.sign({ key: keyObj, dsaEncoding: "ieee-p1363" });
  return {
    signature: "0x" + sig.toString("hex"),
    backend: "skill:crypto-secp256r1.sign",
  };
}

function getUncompressedXY(privBuf) {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(privBuf);
  const pub = ecdh.getPublicKey();
  return pub.subarray(1); // strip 0x04 prefix
}
