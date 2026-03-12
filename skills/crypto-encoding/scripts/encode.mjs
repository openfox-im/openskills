const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function run(input) {
  const { format, data } = input?.request ?? {};
  if (!format) throw new Error("missing request.format");
  if (!data && data !== "") throw new Error("missing request.data (hex input)");
  const buf = Buffer.from(data.replace(/^0x/, ""), "hex");
  let encoded;
  switch (format.toLowerCase()) {
    case "base64":
      encoded = buf.toString("base64");
      break;
    case "hex":
      encoded = "0x" + buf.toString("hex");
      break;
    case "base58":
      encoded = toBase58(buf);
      break;
    default:
      throw new Error(`unsupported format: ${format}. Use base58, base64, or hex`);
  }
  return { encoded, format: format.toLowerCase(), backend: "skill:crypto-encoding.encode" };
}

function toBase58(buf) {
  let num = BigInt("0x" + (buf.toString("hex") || "0"));
  let result = "";
  while (num > 0n) {
    result = BASE58_ALPHABET[Number(num % 58n)] + result;
    num /= 58n;
  }
  for (const b of buf) { if (b === 0) result = "1" + result; else break; }
  return result || "1";
}
