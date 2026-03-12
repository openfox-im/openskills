import { describe, it, expect } from "vitest";
import { createECDH } from "node:crypto";
import { run as sign } from "../skills/crypto-secp256r1/scripts/sign.mjs";
import { run as verify } from "../skills/crypto-secp256r1/scripts/verify.mjs";

describe("crypto-secp256r1", () => {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  const privateKey = ecdh.getPrivateKey("hex");
  const publicKey = "0x" + ecdh.getPublicKey("hex");
  const messageHash = "0x" + "cd".repeat(32);

  it("sign → verify round trip", () => {
    const signed = sign({ request: { privateKey, message: messageHash } });
    expect(signed.signature).toMatch(/^0x[0-9a-f]{128}$/);
    expect(signed.backend).toBe("skill:crypto-secp256r1.sign");

    const verified = verify({
      request: { publicKey, message: messageHash, signature: signed.signature },
    });
    expect(verified.valid).toBe(true);
    expect(verified.backend).toBe("skill:crypto-secp256r1.verify");
  });

  it("verify rejects tampered signature", () => {
    const signed = sign({ request: { privateKey, message: messageHash } });
    const tampered = "0x" + "00".repeat(64);
    const verified = verify({
      request: { publicKey, message: messageHash, signature: tampered },
    });
    expect(verified.valid).toBe(false);
  });

  it("throws on wrong key length", () => {
    expect(() => sign({ request: { privateKey: "aabb", message: messageHash } })).toThrow("32 bytes");
  });
});
