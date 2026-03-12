import { describe, it, expect } from "vitest";
import { run as encode } from "../skills/crypto-encoding/scripts/encode.mjs";
import { run as decode } from "../skills/crypto-encoding/scripts/decode.mjs";

describe("crypto-encoding", () => {
  describe("base64", () => {
    it("encode → decode round trip", () => {
      const data = "0x48656c6c6f"; // "Hello"
      const enc = encode({ request: { format: "base64", data } });
      expect(enc.encoded).toBe("SGVsbG8=");
      expect(enc.backend).toBe("skill:crypto-encoding.encode");

      const dec = decode({ request: { format: "base64", data: enc.encoded } });
      expect(dec.decoded).toBe(data);
      expect(dec.backend).toBe("skill:crypto-encoding.decode");
    });
  });

  describe("hex", () => {
    it("encode → decode round trip", () => {
      const data = "0xdeadbeef";
      const enc = encode({ request: { format: "hex", data } });
      expect(enc.encoded).toBe("0xdeadbeef");

      const dec = decode({ request: { format: "hex", data: enc.encoded } });
      expect(dec.decoded).toBe(data);
    });
  });

  describe("base58", () => {
    it("encode → decode round trip", () => {
      const data = "0x" + "ff".repeat(32);
      const enc = encode({ request: { format: "base58", data } });
      expect(enc.encoded).toBeTruthy();
      expect(enc.encoded).not.toContain("0");  // no '0' in base58
      expect(enc.encoded).not.toContain("O");
      expect(enc.encoded).not.toContain("I");
      expect(enc.encoded).not.toContain("l");

      const dec = decode({ request: { format: "base58", data: enc.encoded } });
      expect(dec.decoded).toBe(data);
    });

    it("handles leading zero bytes", () => {
      const data = "0x0000ff";
      const enc = encode({ request: { format: "base58", data } });
      expect(enc.encoded.startsWith("11")).toBe(true); // two leading '1's for two 0x00 bytes

      const dec = decode({ request: { format: "base58", data: enc.encoded } });
      expect(dec.decoded).toBe(data);
    });

    it("encodes known value", () => {
      // "Hello World" in hex
      const data = "0x48656c6c6f20576f726c64";
      const enc = encode({ request: { format: "base58", data } });
      expect(enc.encoded).toBe("JxF12TrwUP45BMd");
    });
  });

  it("throws on unsupported format", () => {
    expect(() => encode({ request: { format: "bech32", data: "0xff" } })).toThrow("unsupported");
  });

  it("throws on missing fields", () => {
    expect(() => encode({ request: { data: "0xff" } })).toThrow("missing request.format");
    expect(() => encode({ request: { format: "hex" } })).toThrow("missing request.data");
  });
});
