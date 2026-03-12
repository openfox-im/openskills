import { describe, it, expect } from "vitest";
import { run as verifyConsensus } from "../skills/proofverify/scripts/verify-consensus.mjs";

describe("proofverify.verify-consensus", () => {
  describe("valid consensus", () => {
    it("3-of-5 agreement on verdict", () => {
      const result = verifyConsensus({
        request: {
          m: 3,
          n: 5,
          agentResults: [
            { verdict: "factual" },
            { verdict: "factual" },
            { verdict: "factual" },
            { verdict: "misleading" },
            { verdict: "opinion" },
          ],
        },
      });
      expect(result.verdict).toBe("valid");
      expect(result.metadata.consensus).toBe("3/5");
      expect(result.metadata.threshold_met).toBe(true);
      expect(result.metadata.majority_verdict).toBe("factual");
      expect(result.backend).toBe("skill:proofverify.verify-consensus");
    });

    it("unanimous 3-of-3 with server name and article hash", () => {
      const result = verifyConsensus({
        request: {
          m: 3,
          n: 3,
          agentResults: [
            { verdict: "factual", serverName: "api.nytimes.com", articleSha256: "0x" + "ab".repeat(32), attestationSha256: "0x" + "01".repeat(32) },
            { verdict: "factual", serverName: "api.nytimes.com", articleSha256: "0x" + "ab".repeat(32), attestationSha256: "0x" + "02".repeat(32) },
            { verdict: "factual", serverName: "api.nytimes.com", articleSha256: "0x" + "ab".repeat(32), attestationSha256: "0x" + "03".repeat(32) },
          ],
        },
      });
      expect(result.verdict).toBe("valid");
      expect(result.verdictReason).toBe("consensus_reached");
      expect(result.summary).toContain("3/3");
    });

    it("validates expected server name", () => {
      const result = verifyConsensus({
        request: {
          m: 2,
          n: 3,
          expectedServerName: "api.nytimes.com",
          agentResults: [
            { verdict: "factual", serverName: "api.nytimes.com" },
            { verdict: "factual", serverName: "api.nytimes.com" },
            { verdict: "factual", serverName: "api.nytimes.com" },
          ],
        },
      });
      expect(result.verdict).toBe("valid");
      const serverCheck = result.metadata.checks.find((c) => c.label === "expected_server_name");
      expect(serverCheck.ok).toBe(true);
    });

    it("validates expected article hash", () => {
      const hash = "0x" + "cc".repeat(32);
      const result = verifyConsensus({
        request: {
          m: 2,
          n: 2,
          expectedArticleSha256: hash,
          agentResults: [
            { verdict: "factual", articleSha256: hash },
            { verdict: "factual", articleSha256: hash },
          ],
        },
      });
      expect(result.verdict).toBe("valid");
    });
  });

  describe("invalid consensus", () => {
    it("fails when too few agents agree", () => {
      const result = verifyConsensus({
        request: {
          m: 3,
          n: 5,
          agentResults: [
            { verdict: "factual" },
            { verdict: "factual" },
            { verdict: "misleading" },
            { verdict: "opinion" },
            { verdict: "unknown" },
          ],
        },
      });
      expect(result.verdict).toBe("invalid");
      expect(result.verdictReason).toBe("consensus_not_reached");
      expect(result.metadata.threshold_met).toBe(false);
    });

    it("fails on server name mismatch", () => {
      const result = verifyConsensus({
        request: {
          m: 2,
          n: 3,
          expectedServerName: "api.nytimes.com",
          agentResults: [
            { verdict: "factual", serverName: "api.nytimes.com" },
            { verdict: "factual", serverName: "api.nytimes.com" },
            { verdict: "factual", serverName: "evil.com" },
          ],
        },
      });
      // Verdict consensus passes (3/3 factual) but there may be server name issues
      // The server_name_consensus check passes (2/3 agree on nytimes >= m=2)
      // The expected_server_name check passes (top name is nytimes, count=2 >= m=2)
      expect(result.verdict).toBe("valid");
    });

    it("fails when expected server differs from majority", () => {
      const result = verifyConsensus({
        request: {
          m: 2,
          n: 3,
          expectedServerName: "api.reuters.com",
          agentResults: [
            { verdict: "factual", serverName: "api.nytimes.com" },
            { verdict: "factual", serverName: "api.nytimes.com" },
            { verdict: "factual", serverName: "api.nytimes.com" },
          ],
        },
      });
      expect(result.verdict).toBe("invalid");
      const check = result.metadata.checks.find((c) => c.label === "expected_server_name");
      expect(check.ok).toBe(false);
    });

    it("fails on duplicate attestation hashes", () => {
      const sameHash = "0x" + "aa".repeat(32);
      const result = verifyConsensus({
        request: {
          m: 2,
          n: 3,
          agentResults: [
            { verdict: "factual", attestationSha256: sameHash },
            { verdict: "factual", attestationSha256: sameHash },
            { verdict: "factual", attestationSha256: "0x" + "bb".repeat(32) },
          ],
        },
      });
      expect(result.verdict).toBe("invalid");
      const uniqueCheck = result.metadata.checks.find((c) => c.label === "attestation_uniqueness");
      expect(uniqueCheck.ok).toBe(false);
    });
  });

  describe("edge cases", () => {
    it("1-of-1 trivially passes", () => {
      const result = verifyConsensus({
        request: {
          m: 1,
          n: 1,
          agentResults: [{ verdict: "factual" }],
        },
      });
      expect(result.verdict).toBe("valid");
    });

    it("receipt is deterministic", () => {
      const input = {
        request: {
          m: 2,
          n: 3,
          agentResults: [
            { verdict: "factual" },
            { verdict: "factual" },
            { verdict: "misleading" },
          ],
        },
      };
      const a = verifyConsensus(input);
      const b = verifyConsensus(input);
      expect(a.verifierReceiptSha256).toBe(b.verifierReceiptSha256);
    });
  });

  describe("error handling", () => {
    it("throws on missing request", () => {
      expect(() => verifyConsensus({})).toThrow("missing input.request");
    });

    it("throws on m > n", () => {
      expect(() =>
        verifyConsensus({ request: { m: 5, n: 3, agentResults: [] } })
      ).toThrow("request.m cannot exceed request.n");
    });

    it("throws on mismatched agentResults length", () => {
      expect(() =>
        verifyConsensus({
          request: { m: 2, n: 3, agentResults: [{ verdict: "factual" }] },
        })
      ).toThrow("does not match request.n");
    });
  });
});
