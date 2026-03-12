import { createPrivateKey, createPublicKey, diffieHellman } from "node:crypto";

export function run(input) {
  const { privateKey, peerPublicKey } = input?.request ?? {};
  if (!privateKey) throw new Error("missing request.privateKey");
  if (!peerPublicKey) throw new Error("missing request.peerPublicKey");
  const privBuf = Buffer.from(privateKey.replace(/^0x/, ""), "hex");
  if (privBuf.length !== 32) throw new Error("privateKey must be 32 bytes");
  const pubBuf = Buffer.from(peerPublicKey.replace(/^0x/, ""), "hex");
  if (pubBuf.length !== 32) throw new Error("peerPublicKey must be 32 bytes");
  const privPkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b656e04220420", "hex"), privBuf,
  ]);
  const pubSpki = Buffer.concat([
    Buffer.from("302a300506032b656e032100", "hex"), pubBuf,
  ]);
  const privKey = createPrivateKey({ key: privPkcs8, format: "der", type: "pkcs8" });
  const pubKey = createPublicKey({ key: pubSpki, format: "der", type: "spki" });
  const shared = diffieHellman({ privateKey: privKey, publicKey: pubKey });
  return {
    sharedSecret: "0x" + shared.toString("hex"),
    backend: "skill:crypto-x25519.exchange",
  };
}
