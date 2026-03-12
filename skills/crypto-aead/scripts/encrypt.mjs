import { createCipheriv } from "node:crypto";

const ALGOS = {
  "aes-256-gcm": { cipher: "aes-256-gcm", keyLen: 32, nonceLen: 12 },
  "chacha20-poly1305": { cipher: "chacha20-poly1305", keyLen: 32, nonceLen: 12 },
};

export function run(input) {
  const { algorithm, key, nonce, plaintext, aad } = input?.request ?? {};
  if (!algorithm) throw new Error("missing request.algorithm");
  if (!key) throw new Error("missing request.key");
  if (!nonce) throw new Error("missing request.nonce");
  if (plaintext == null) throw new Error("missing request.plaintext");
  const spec = ALGOS[algorithm.toLowerCase()];
  if (!spec) throw new Error(`unsupported algorithm: ${algorithm}. Use aes-256-gcm or chacha20-poly1305`);
  const keyBuf = Buffer.from(key.replace(/^0x/, ""), "hex");
  if (keyBuf.length !== spec.keyLen) throw new Error(`key must be ${spec.keyLen} bytes`);
  const nonceBuf = Buffer.from(nonce.replace(/^0x/, ""), "hex");
  if (nonceBuf.length !== spec.nonceLen) throw new Error(`nonce must be ${spec.nonceLen} bytes`);
  const ptBuf = Buffer.from(plaintext.replace(/^0x/, ""), "hex");
  const cipher = createCipheriv(spec.cipher, keyBuf, nonceBuf, { authTagLength: 16 });
  if (aad) cipher.setAAD(Buffer.from(aad.replace(/^0x/, ""), "hex"));
  const ct = Buffer.concat([cipher.update(ptBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    ciphertext: "0x" + ct.toString("hex"),
    tag: "0x" + tag.toString("hex"),
    backend: "skill:crypto-aead.encrypt",
  };
}
