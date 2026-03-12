import { createHash } from "node:crypto";

const SUPPORTED = {
  sha256: { name: "sha256", bytes: 32 },
  sha512: { name: "sha512", bytes: 64 },
  "sha3-256": { name: "sha3-256", bytes: 32 },
  keccak256: { name: "sha3-256", bytes: 32 },
  sha1: { name: "sha1", bytes: 20 },
  ripemd160: { name: "ripemd160", bytes: 20 },
  blake2b512: { name: "blake2b512", bytes: 64 },
};

export function run(input) {
  const { algorithm, data, encoding } = input?.request ?? {};
  if (!algorithm) throw new Error("missing request.algorithm");
  if (!data) throw new Error("missing request.data");
  const spec = SUPPORTED[algorithm.toLowerCase()];
  if (!spec) throw new Error(`unsupported algorithm: ${algorithm}`);
  const enc = encoding === "utf8" ? "utf8" : "hex";
  const buf = enc === "hex" ? Buffer.from(data.replace(/^0x/, ""), "hex") : Buffer.from(data, "utf8");
  const digest = createHash(spec.name).update(buf).digest("hex");
  return {
    hash: "0x" + digest,
    algorithm: algorithm.toLowerCase(),
    bytes: spec.bytes,
    backend: "skill:crypto-hash.hash",
  };
}
