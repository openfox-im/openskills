import { describe, it, expect } from "vitest";
import { run as schnorrSign } from "../skills/crypto-schnorr/scripts/sign.mjs";
import { run as schnorrVerify } from "../skills/crypto-schnorr/scripts/verify.mjs";
import { run as vrfProve } from "../skills/crypto-vrf/scripts/prove.mjs";
import { run as vrfVerify } from "../skills/crypto-vrf/scripts/verify.mjs";
import { run as blsPairing } from "../skills/crypto-bls12-381/scripts/pairing.mjs";
import { run as bn254Pairing } from "../skills/crypto-bn254/scripts/pairing.mjs";
import { run as rangeVerify } from "../skills/crypto-rangeproofs/scripts/verify.mjs";
import { run as unoVerify } from "../skills/crypto-uno-proofs/scripts/verify.mjs";
import { run as elgamalEncrypt } from "../skills/crypto-x25519/scripts/encrypt.mjs";

describe("native-only stubs return structured errors", () => {
  it("crypto-schnorr sign", () => {
    const r = schnorrSign({ request: { privateKey: "aa".repeat(32), message: "bb".repeat(32) } });
    expect(r.error).toContain("native binding required");
    expect(r.backend).toBe("skill:crypto-schnorr.sign");
  });

  it("crypto-schnorr verify", () => {
    const r = schnorrVerify({ request: { publicKey: "aa".repeat(32), message: "bb".repeat(32), signature: "cc".repeat(64) } });
    expect(r.error).toContain("native binding required");
    expect(r.backend).toBe("skill:crypto-schnorr.verify");
  });

  it("crypto-vrf prove", () => {
    const r = vrfProve({ request: { privateKey: "aa".repeat(32), alpha: "bb".repeat(16) } });
    expect(r.error).toContain("native binding required");
    expect(r.backend).toBe("skill:crypto-vrf.prove");
  });

  it("crypto-vrf verify", () => {
    const r = vrfVerify({ request: { publicKey: "aa".repeat(32), alpha: "bb", proof: "cc".repeat(40) } });
    expect(r.error).toContain("native binding required");
    expect(r.backend).toBe("skill:crypto-vrf.verify");
  });

  it("crypto-bls12-381 pairing", () => {
    const r = blsPairing({ request: { g1Point: "aa".repeat(48), g2Point: "bb".repeat(96) } });
    expect(r.error).toContain("native binding required");
    expect(r.backend).toBe("skill:crypto-bls12-381.pairing");
  });

  it("crypto-bn254 pairing", () => {
    const r = bn254Pairing({ request: { g1Point: "aa".repeat(32), g2Point: "bb".repeat(64) } });
    expect(r.error).toContain("native binding required");
    expect(r.backend).toBe("skill:crypto-bn254.pairing");
  });

  it("crypto-rangeproofs verify", () => {
    const r = rangeVerify({ request: { commitment: "aa".repeat(32), proof: "bb".repeat(64) } });
    expect(r.error).toContain("native binding required");
    expect(r.backend).toBe("skill:crypto-rangeproofs.verify");
  });

  it("crypto-uno-proofs verify", () => {
    const r = unoVerify({ request: { proof: "aa".repeat(32), publicInputs: ["bb"] } });
    expect(r.error).toContain("native binding required");
    expect(r.backend).toBe("skill:crypto-uno-proofs.verify");
  });

  it("crypto-x25519 elgamal encrypt", () => {
    const r = elgamalEncrypt({ request: { publicKey: "aa".repeat(32), plaintext: "bb" } });
    expect(r.error).toContain("native binding required");
    expect(r.backend).toBe("skill:crypto-x25519.encrypt");
  });
});
