---
name: crypto-encoding
description: "Cryptographic data encoding — Base58, Base64, Bech32, and TOS-compatible address serialization. Use when: encoding binary data for display, address formatting, QR code payloads, human-readable binary representation. NOT for: encryption, compression, or general text encoding (use standard UTF-8)."
license: MIT
metadata: { "openfox": { "requires": { "bins": ["node"] }, "provider-backends": { "encode": { "entry": "scripts/encode.mjs", "description": "Encode binary data to Base58/Base64/hex" }, "decode": { "entry": "scripts/decode.mjs", "description": "Decode Base58/Base64/hex to binary" } } } }
---

This skill handles encoding and decoding of cryptographic data into human-readable and transport-safe formats. Base58 encoding (Bitcoin-style alphabet, no 0/O/I/l ambiguity) is optimized for common sizes of 32 bytes and 64 bytes, with a general-purpose path for arbitrary lengths. Base64 provides standard RFC 4648 encoding. Bech32 encoding includes a checksum and is used for TOS network addresses with the "tos" prefix for mainnet and "tst" prefix for testnet, performing 8-bit to 5-bit conversion internally.

TOS address serialization supports two types: normal addresses (type 0) consisting of a 32-byte public key hash, and data-embedded addresses (type 1) that can carry up to 128 bytes of integrated data alongside the address. The encode backend accepts raw bytes and a format specifier, returning the encoded string. The decode backend accepts an encoded string and returns the raw bytes along with metadata (e.g., detected format, network prefix, address type).

Header references: `lib/include/at/crypto/at_base58.h`, `at_base64.h`, `at_bech32.h`, `at_address.h`. When working with TOS addresses, always use Bech32 encoding with the appropriate network prefix — do not manually construct address strings. The Bech32 checksum detects up to 4 character errors and any transposition of adjacent characters. Data-embedded addresses (type 1) should be validated for maximum payload size (128 bytes) before encoding. Base58 decoding should always validate the expected output length to prevent buffer issues.
