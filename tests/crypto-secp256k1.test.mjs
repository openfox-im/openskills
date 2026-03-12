import { describe, it, expect } from "vitest";
import { createECDH } from "node:crypto";
import { run as sign } from "../skills/crypto-secp256k1/scripts/sign.mjs";
import { run as verify } from "../skills/crypto-secp256k1/scripts/verify.mjs";

describe("crypto-secp256k1", () => {
  // Generate a valid secp256k1 keypair
  const ecdh = createECDH("secp256k1");
  ecdh.generateKeys();
  const privateKey = ecdh.getPrivateKey("hex");
  const publicKey = "0x" + ecdh.getPublicKey("hex"); // uncompressed 65 bytes
  const messageHash = "0x" + "ab".repeat(32); // 32 byte pre-hashed message

  it("sign returns signature and recovery id", () => {
    const result = sign({ request: { privateKey, message: messageHash } });
    expect(result.signature).toMatch(/^0x[0-9a-f]{128}$/); // 64 bytes r||s
    expect(typeof result.recoveryId).toBe("number");
    expect(result.backend).toBe("skill:crypto-secp256k1.sign");
  });

  it("sign → verify round trip", () => {
    const signed = sign({ request: { privateKey, message: messageHash } });
    const verified = verify({
      request: { publicKey, message: messageHash, signature: signed.signature },
    });
    expect(verified.valid).toBe(true);
    expect(verified.backend).toBe("skill:crypto-secp256k1.verify");
  });

  it("verify rejects wrong message", () => {
    const signed = sign({ request: { privateKey, message: messageHash } });
    const verified = verify({
      request: { publicKey, message: "0x" + "00".repeat(32), signature: signed.signature },
    });
    expect(verified.valid).toBe(false);
  });

  it("throws on non-32-byte message", () => {
    expect(() =>
      sign({ request: { privateKey, message: "0xaabb" } }),
    ).toThrow("32 bytes");
  });

  it("throws on missing fields", () => {
    expect(() => sign({ request: { message: messageHash } })).toThrow("missing request.privateKey");
    expect(() => verify({ request: { publicKey } })).toThrow("missing request.message");
  });
});
