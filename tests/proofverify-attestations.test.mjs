import { describe, it, expect } from "vitest";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { run as verifyAttestations } from "../skills/proofverify/scripts/verify-attestations.mjs";

const nativeAvailable = existsSync(
  join(homedir(), ".agents", "skills", "openskills", "native", "openskills-zktls.node")
) || existsSync(
  new URL("../native/openskills-zktls.node", import.meta.url)
);

describe("proofverify.verify-attestations", () => {
  describe("error handling", () => {
    it("throws on missing request", async () => {
      await expect(verifyAttestations({})).rejects.toThrow("missing input.request");
    });

    it("throws on missing attestations", async () => {
      await expect(
        verifyAttestations({ request: {} })
      ).rejects.toThrow("missing or invalid request.attestations");
    });

    it("throws on empty attestations array", async () => {
      await expect(
        verifyAttestations({ request: { attestations: [] } })
      ).rejects.toThrow("must contain at least one attestation");
    });

    it("throws on non-array attestations", async () => {
      await expect(
        verifyAttestations({ request: { attestations: "not-array" } })
      ).rejects.toThrow("missing or invalid request.attestations");
    });
  });

  describe("native module fallback", () => {
    it("returns structured error or invalid result for bad attestation", async () => {
      const result = await verifyAttestations({
        request: {
          attestations: ['{"invalid": "attestation"}'],
        },
      });
      if (result.error) {
        expect(result.error).toContain("native binding required");
        expect(result.backend).toBe("skill:proofverify.verify-attestations");
      } else {
        expect(result.verdict).toBe("invalid");
        expect(result.metadata.valid_attestations).toBe(0);
        expect(result.metadata.total_attestations).toBe(1);
      }
    });
  });

  describe("with native module (integration)", () => {
    it.skipIf(!nativeAvailable)("detects invalid attestation structure", async () => {
      const result = await verifyAttestations({
        request: {
          attestations: ['{"not": "a valid attestation"}'],
        },
      });
      expect(result.verdict).toBe("invalid");
      expect(result.metadata.total_attestations).toBe(1);
      expect(result.metadata.valid_attestations).toBe(0);
      expect(result.metadata.results[0].valid).toBe(false);
    });

    it.skipIf(!nativeAvailable)("handles mixed entries including empty strings", async () => {
      const result = await verifyAttestations({
        request: {
          attestations: [
            '{"not": "valid"}',
            '',
            '{"also": "invalid"}',
          ],
        },
      });
      expect(result.verdict).toBe("invalid");
      expect(result.metadata.total_attestations).toBe(3);
      expect(result.metadata.valid_attestations).toBe(0);
      const validityCheck = result.metadata.checks.find((c) => c.label === "attestation_validity");
      expect(validityCheck.ok).toBe(false);
    });
  });
});
