# crypto-encoding — encode / decode backends

## encode

### Input
- `request.format` — Encoding format (base58, base64, bech32, hex)
- `request.data` — Hex-encoded input data

### Output
- `encoded` — Encoded output string
- `format` — Format used
- `backend` — "skill:crypto-encoding.encode"

## decode

### Input
- `request.format` — Encoding format (base58, base64, bech32, hex)
- `request.encoded` — Encoded string to decode

### Output
- `data` — Hex-encoded decoded data
- `format` — Format used
- `backend` — "skill:crypto-encoding.decode"
