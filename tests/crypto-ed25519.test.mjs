import { describe, it, expect } from "vitest";
import { run as sign } from "../skills/crypto-ed25519/scripts/sign.mjs";
import { run as verify } from "../skills/crypto-ed25519/scripts/verify.mjs";

describe("crypto-ed25519", () => {
  // Known test key (32 bytes of zeros is a valid Ed25519 seed)
  const privateKey = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
  const message = "0x68656c6c6f"; // "hello"

  it("sign returns signature and public key", () => {
    const result = sign({ request: { privateKey, message } });
    expect(result.signature).toMatch(/^0x[0-9a-f]{128}$/); // 64 bytes
    expect(result.publicKey).toMatch(/^0x[0-9a-f]{64}$/);  // 32 bytes
    expect(result.backend).toBe("skill:crypto-ed25519.sign");
  });

  it("sign → verify round trip", () => {
    const signed = sign({ request: { privateKey, message } });
    const verified = verify({
      request: {
        publicKey: signed.publicKey,
        message,
        signature: signed.signature,
      },
    });
    expect(verified.valid).toBe(true);
    expect(verified.backend).toBe("skill:crypto-ed25519.verify");
  });

  it("verify rejects wrong message", () => {
    const signed = sign({ request: { privateKey, message } });
    const verified = verify({
      request: {
        publicKey: signed.publicKey,
        message: "0x" + "00".repeat(5),
        signature: signed.signature,
      },
    });
    expect(verified.valid).toBe(false);
  });

  it("verify rejects tampered signature", () => {
    const signed = sign({ request: { privateKey, message } });
    const tampered = signed.signature.slice(0, -2) + "ff";
    const verified = verify({
      request: {
        publicKey: signed.publicKey,
        message,
        signature: tampered,
      },
    });
    expect(verified.valid).toBe(false);
  });

  it("sign throws on wrong key length", () => {
    expect(() => sign({ request: { privateKey: "aabb", message } })).toThrow("32 bytes");
  });

  it("verify throws on wrong signature length", () => {
    const signed = sign({ request: { privateKey, message } });
    expect(() =>
      verify({ request: { publicKey: signed.publicKey, message, signature: "0xaabb" } }),
    ).toThrow("64 bytes");
  });

  it("deterministic: same input → same signature", () => {
    const s1 = sign({ request: { privateKey, message } });
    const s2 = sign({ request: { privateKey, message } });
    expect(s1.signature).toBe(s2.signature);
  });
});
