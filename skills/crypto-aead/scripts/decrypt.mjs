import { createDecipheriv } from "node:crypto";

const ALGOS = {
  "aes-256-gcm": { cipher: "aes-256-gcm", keyLen: 32, nonceLen: 12 },
  "chacha20-poly1305": { cipher: "chacha20-poly1305", keyLen: 32, nonceLen: 12 },
};

export function run(input) {
  const { algorithm, key, nonce, ciphertext, tag, aad } = input?.request ?? {};
  if (!algorithm) throw new Error("missing request.algorithm");
  if (!key) throw new Error("missing request.key");
  if (!nonce) throw new Error("missing request.nonce");
  if (!ciphertext) throw new Error("missing request.ciphertext");
  if (!tag) throw new Error("missing request.tag");
  const spec = ALGOS[algorithm.toLowerCase()];
  if (!spec) throw new Error(`unsupported algorithm: ${algorithm}`);
  const keyBuf = Buffer.from(key.replace(/^0x/, ""), "hex");
  if (keyBuf.length !== spec.keyLen) throw new Error(`key must be ${spec.keyLen} bytes`);
  const nonceBuf = Buffer.from(nonce.replace(/^0x/, ""), "hex");
  if (nonceBuf.length !== spec.nonceLen) throw new Error(`nonce must be ${spec.nonceLen} bytes`);
  const ctBuf = Buffer.from(ciphertext.replace(/^0x/, ""), "hex");
  const tagBuf = Buffer.from(tag.replace(/^0x/, ""), "hex");
  const decipher = createDecipheriv(spec.cipher, keyBuf, nonceBuf, { authTagLength: 16 });
  decipher.setAuthTag(tagBuf);
  if (aad) decipher.setAAD(Buffer.from(aad.replace(/^0x/, ""), "hex"));
  const pt = Buffer.concat([decipher.update(ctBuf), decipher.final()]);
  return {
    plaintext: "0x" + pt.toString("hex"),
    backend: "skill:crypto-aead.decrypt",
  };
}
