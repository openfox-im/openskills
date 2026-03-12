import { describe, it, expect } from "vitest";
import { run } from "../skills/crypto-hash/scripts/hash.mjs";

describe("crypto-hash", () => {
  it("computes SHA-256", () => {
    const result = run({ request: { algorithm: "sha256", data: "68656c6c6f" } });
    expect(result.hash).toBe("0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    expect(result.bytes).toBe(32);
    expect(result.backend).toBe("skill:crypto-hash.hash");
  });

  it("computes SHA-512", () => {
    const result = run({ request: { algorithm: "sha512", data: "68656c6c6f" } });
    expect(result.hash).toMatch(/^0x[0-9a-f]{128}$/);
    expect(result.bytes).toBe(64);
  });

  it("computes Keccak-256 (via sha3-256)", () => {
    const r1 = run({ request: { algorithm: "sha3-256", data: "68656c6c6f" } });
    const r2 = run({ request: { algorithm: "keccak256", data: "68656c6c6f" } });
    expect(r1.hash).toBe(r2.hash);
    expect(r1.bytes).toBe(32);
  });

  it("computes SHA-1", () => {
    const result = run({ request: { algorithm: "sha1", data: "68656c6c6f" } });
    expect(result.hash).toBe("0xaaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d");
    expect(result.bytes).toBe(20);
  });

  it("computes RIPEMD-160", () => {
    const result = run({ request: { algorithm: "ripemd160", data: "68656c6c6f" } });
    expect(result.hash).toMatch(/^0x[0-9a-f]{40}$/);
    expect(result.bytes).toBe(20);
  });

  it("computes BLAKE2b-512", () => {
    const result = run({ request: { algorithm: "blake2b512", data: "68656c6c6f" } });
    expect(result.hash).toMatch(/^0x[0-9a-f]{128}$/);
    expect(result.bytes).toBe(64);
  });

  it("supports utf8 encoding", () => {
    const result = run({ request: { algorithm: "sha256", data: "hello", encoding: "utf8" } });
    expect(result.hash).toBe("0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  });

  it("supports 0x-prefixed hex input", () => {
    const result = run({ request: { algorithm: "sha256", data: "0x68656c6c6f" } });
    expect(result.hash).toBe("0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  });

  it("throws on missing algorithm", () => {
    expect(() => run({ request: { data: "ff" } })).toThrow("missing request.algorithm");
  });

  it("throws on unsupported algorithm", () => {
    expect(() => run({ request: { algorithm: "md4", data: "ff" } })).toThrow("unsupported");
  });

  it("hashes empty input", () => {
    const result = run({ request: { algorithm: "sha256", data: "0x" } });
    expect(result.hash).toBe("0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
});
