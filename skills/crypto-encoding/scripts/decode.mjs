const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function run(input) {
  const { format, data } = input?.request ?? {};
  if (!format) throw new Error("missing request.format");
  if (!data && data !== "") throw new Error("missing request.data");
  let buf;
  switch (format.toLowerCase()) {
    case "base64":
      buf = Buffer.from(data, "base64");
      break;
    case "hex":
      buf = Buffer.from(data.replace(/^0x/, ""), "hex");
      break;
    case "base58":
      buf = fromBase58(data);
      break;
    default:
      throw new Error(`unsupported format: ${format}. Use base58, base64, or hex`);
  }
  return {
    decoded: "0x" + buf.toString("hex"),
    format: format.toLowerCase(),
    backend: "skill:crypto-encoding.decode",
  };
}

function fromBase58(str) {
  let num = 0n;
  for (const ch of str) {
    const idx = BASE58_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`invalid base58 character: ${ch}`);
    num = num * 58n + BigInt(idx);
  }
  const hex = num === 0n ? "" : num.toString(16).padStart(num.toString(16).length + (num.toString(16).length % 2), "0");
  const prefix = [];
  for (const ch of str) { if (ch === "1") prefix.push(0); else break; }
  return Buffer.from([...prefix, ...Buffer.from(hex, "hex")]);
}
