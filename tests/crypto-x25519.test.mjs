import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { run as exchange } from "../skills/crypto-x25519/scripts/exchange.mjs";

describe("crypto-x25519", () => {
  function genX25519() {
    const kp = generateKeyPairSync("x25519");
    const priv = kp.privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
    const pub = kp.publicKey.export({ format: "der", type: "spki" }).subarray(-32);
    return { privateKey: priv.toString("hex"), publicKey: pub.toString("hex") };
  }

  it("ECDH produces 32-byte shared secret", () => {
    const alice = genX25519();
    const bob = genX25519();
    const result = exchange({
      request: { privateKey: alice.privateKey, peerPublicKey: bob.publicKey },
    });
    expect(result.sharedSecret).toMatch(/^0x[0-9a-f]{64}$/);
    expect(result.backend).toBe("skill:crypto-x25519.exchange");
  });

  it("shared secret is symmetric (Alice↔Bob)", () => {
    const alice = genX25519();
    const bob = genX25519();
    const ab = exchange({
      request: { privateKey: alice.privateKey, peerPublicKey: bob.publicKey },
    });
    const ba = exchange({
      request: { privateKey: bob.privateKey, peerPublicKey: alice.publicKey },
    });
    expect(ab.sharedSecret).toBe(ba.sharedSecret);
  });

  it("different peers produce different secrets", () => {
    const alice = genX25519();
    const bob = genX25519();
    const charlie = genX25519();
    const ab = exchange({
      request: { privateKey: alice.privateKey, peerPublicKey: bob.publicKey },
    });
    const ac = exchange({
      request: { privateKey: alice.privateKey, peerPublicKey: charlie.publicKey },
    });
    expect(ab.sharedSecret).not.toBe(ac.sharedSecret);
  });

  it("throws on wrong key length", () => {
    expect(() =>
      exchange({ request: { privateKey: "aabb", peerPublicKey: "00".repeat(32) } }),
    ).toThrow("32 bytes");
  });
});
