import { describe, it, expect } from "vitest";
import { run as encrypt } from "../skills/crypto-aead/scripts/encrypt.mjs";
import { run as decrypt } from "../skills/crypto-aead/scripts/decrypt.mjs";
import { randomBytes } from "node:crypto";

describe("crypto-aead", () => {
  const key32 = randomBytes(32).toString("hex");
  const nonce12 = randomBytes(12).toString("hex");
  const plaintext = "0x48656c6c6f20576f726c6421"; // "Hello World!"

  describe("AES-256-GCM", () => {
    it("encrypt → decrypt round trip", () => {
      const enc = encrypt({
        request: { algorithm: "aes-256-gcm", key: key32, nonce: nonce12, plaintext },
      });
      expect(enc.ciphertext).toMatch(/^0x[0-9a-f]+$/);
      expect(enc.tag).toMatch(/^0x[0-9a-f]{32}$/); // 16 bytes
      expect(enc.backend).toBe("skill:crypto-aead.encrypt");

      const dec = decrypt({
        request: {
          algorithm: "aes-256-gcm",
          key: key32,
          nonce: nonce12,
          ciphertext: enc.ciphertext,
          tag: enc.tag,
        },
      });
      expect(dec.plaintext).toBe(plaintext);
      expect(dec.backend).toBe("skill:crypto-aead.decrypt");
    });

    it("decrypt fails with wrong key", () => {
      const enc = encrypt({
        request: { algorithm: "aes-256-gcm", key: key32, nonce: nonce12, plaintext },
      });
      const wrongKey = randomBytes(32).toString("hex");
      expect(() =>
        decrypt({
          request: {
            algorithm: "aes-256-gcm",
            key: wrongKey,
            nonce: nonce12,
            ciphertext: enc.ciphertext,
            tag: enc.tag,
          },
        }),
      ).toThrow();
    });

    it("decrypt fails with tampered tag", () => {
      const enc = encrypt({
        request: { algorithm: "aes-256-gcm", key: key32, nonce: nonce12, plaintext },
      });
      expect(() =>
        decrypt({
          request: {
            algorithm: "aes-256-gcm",
            key: key32,
            nonce: nonce12,
            ciphertext: enc.ciphertext,
            tag: "0x" + "00".repeat(16),
          },
        }),
      ).toThrow();
    });

    it("supports AAD (additional authenticated data)", () => {
      const aad = "0xdeadbeef";
      const enc = encrypt({
        request: { algorithm: "aes-256-gcm", key: key32, nonce: nonce12, plaintext, aad },
      });
      const dec = decrypt({
        request: {
          algorithm: "aes-256-gcm",
          key: key32,
          nonce: nonce12,
          ciphertext: enc.ciphertext,
          tag: enc.tag,
          aad,
        },
      });
      expect(dec.plaintext).toBe(plaintext);

      // Wrong AAD should fail
      expect(() =>
        decrypt({
          request: {
            algorithm: "aes-256-gcm",
            key: key32,
            nonce: nonce12,
            ciphertext: enc.ciphertext,
            tag: enc.tag,
            aad: "0xcafebabe",
          },
        }),
      ).toThrow();
    });
  });

  describe("ChaCha20-Poly1305", () => {
    it("encrypt → decrypt round trip", () => {
      const enc = encrypt({
        request: { algorithm: "chacha20-poly1305", key: key32, nonce: nonce12, plaintext },
      });
      expect(enc.ciphertext).toMatch(/^0x[0-9a-f]+$/);
      expect(enc.tag).toMatch(/^0x[0-9a-f]{32}$/);

      const dec = decrypt({
        request: {
          algorithm: "chacha20-poly1305",
          key: key32,
          nonce: nonce12,
          ciphertext: enc.ciphertext,
          tag: enc.tag,
        },
      });
      expect(dec.plaintext).toBe(plaintext);
    });

    it("AES and ChaCha produce different ciphertexts", () => {
      const aes = encrypt({
        request: { algorithm: "aes-256-gcm", key: key32, nonce: nonce12, plaintext },
      });
      const chacha = encrypt({
        request: { algorithm: "chacha20-poly1305", key: key32, nonce: nonce12, plaintext },
      });
      expect(aes.ciphertext).not.toBe(chacha.ciphertext);
    });
  });

  it("throws on unsupported algorithm", () => {
    expect(() =>
      encrypt({ request: { algorithm: "rc4", key: key32, nonce: nonce12, plaintext } }),
    ).toThrow("unsupported");
  });

  it("throws on wrong key length", () => {
    expect(() =>
      encrypt({ request: { algorithm: "aes-256-gcm", key: "aabb", nonce: nonce12, plaintext } }),
    ).toThrow("32 bytes");
  });

  it("encrypts empty plaintext", () => {
    const enc = encrypt({
      request: { algorithm: "aes-256-gcm", key: key32, nonce: nonce12, plaintext: "0x" },
    });
    const dec = decrypt({
      request: {
        algorithm: "aes-256-gcm",
        key: key32,
        nonce: nonce12,
        ciphertext: enc.ciphertext,
        tag: enc.tag,
      },
    });
    expect(dec.plaintext).toBe("0x");
  });
});
