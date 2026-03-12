import { createSign, createECDH, createPrivateKey } from "node:crypto";

export function run(input) {
  const { privateKey, message } = input?.request ?? {};
  if (!privateKey) throw new Error("missing request.privateKey");
  if (!message) throw new Error("missing request.message");
  const keyBuf = Buffer.from(privateKey.replace(/^0x/, ""), "hex");
  if (keyBuf.length !== 32) throw new Error("privateKey must be 32 bytes");
  const msgBuf = Buffer.from(message.replace(/^0x/, ""), "hex");
  if (msgBuf.length !== 32) throw new Error("message must be 32 bytes (pre-hashed)");
  // Build DER-encoded EC private key for secp256k1
  const ecPriv = Buffer.concat([
    Buffer.from("30740201010420", "hex"), keyBuf,
    Buffer.from("a00706052b8104000aa144034200", "hex"),
    getUncompressedPub(keyBuf),
  ]);
  const keyObj = createPrivateKey({ key: ecPriv, format: "der", type: "sec1" });
  const signer = createSign("SHA256");
  signer.update(msgBuf);
  signer.end();
  const derSig = signer.sign({ key: keyObj, dsaEncoding: "ieee-p1363" });
  const r = derSig.subarray(0, 32);
  const s = derSig.subarray(32, 64);
  return {
    signature: "0x" + Buffer.concat([r, s]).toString("hex"),
    recoveryId: 0, // approximate; exact recovery requires EC point math
    backend: "skill:crypto-secp256k1.sign",
  };
}

function getUncompressedPub(privBuf) {
  const ecdh = createECDH("secp256k1");
  ecdh.setPrivateKey(privBuf);
  return ecdh.getPublicKey();
}
