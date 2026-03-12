import { describe, it, expect } from "vitest";
import { run as prove } from "../skills/zktls/scripts/prove.mjs";
import { run as verifyAttestation } from "../skills/zktls/scripts/verify-attestation.mjs";

describe("zktls native stubs (without native module)", () => {
  it("prove returns structured error without native binding", async () => {
    const result = await prove({
      request: {
        serverHost: "example.com",
        notaryHost: "127.0.0.1",
        method: "GET",
        path: "/",
      },
    });
    expect(result.error).toContain("native binding required");
    expect(result.backend).toBe("skill:zktls.prove");
  });

  it("verify-attestation returns structured error without native binding", async () => {
    const result = await verifyAttestation({
      request: {
        attestation: '{"test": true}',
      },
    });
    expect(result.error).toContain("native binding required");
    expect(result.backend).toBe("skill:zktls.verify-attestation");
  });

  it("prove throws on missing serverHost", async () => {
    await expect(prove({ request: { notaryHost: "x", method: "GET", path: "/" } }))
      .rejects.toThrow("missing request.serverHost");
  });

  it("prove throws on missing notaryHost", async () => {
    await expect(prove({ request: { serverHost: "x", method: "GET", path: "/" } }))
      .rejects.toThrow("missing request.notaryHost");
  });

  it("prove throws on missing method", async () => {
    await expect(prove({ request: { serverHost: "x", notaryHost: "x", path: "/" } }))
      .rejects.toThrow("missing request.method");
  });

  it("verify-attestation throws on missing attestation", async () => {
    await expect(verifyAttestation({ request: {} }))
      .rejects.toThrow("missing request.attestation");
  });

  it("verify-attestation throws on missing request", async () => {
    await expect(verifyAttestation({}))
      .rejects.toThrow("missing input.request");
  });
});
