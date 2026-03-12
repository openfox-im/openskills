/* Avatar Base64 encoding implementation for WebSocket handshake.

   Based on RFC 4648 specification. */

#include "at/crypto/at_base64.h"
#include "at/infra/at_util.h"

/* Base64 alphabet (standard, NOT base64url) */
static char const base64_table[64] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

ulong
at_base64_encode( uchar const * in,
                  ulong         in_len,
                  char *        out,
                  ulong         out_sz ) {

  /* Calculate required output size */
  ulong out_len = ((in_len + 2UL) / 3UL) * 4UL;

  /* Check if output buffer is large enough */
  if( out_sz < out_len ) {
    return 0;
  }

  ulong in_pos  = 0;
  ulong out_pos = 0;

  /* Process complete 3-byte groups */
  while( in_pos + 3 <= in_len ) {
    /* Read 3 bytes (24 bits) */
    uint b0 = in[in_pos++];
    uint b1 = in[in_pos++];
    uint b2 = in[in_pos++];

    /* Convert to 4 Base64 characters (6 bits each) */
    out[out_pos++] = base64_table[(b0 >> 2) & 0x3F];
    out[out_pos++] = base64_table[((b0 << 4) | (b1 >> 4)) & 0x3F];
    out[out_pos++] = base64_table[((b1 << 2) | (b2 >> 6)) & 0x3F];
    out[out_pos++] = base64_table[b2 & 0x3F];
  }

  /* Handle remaining bytes (0, 1, or 2 bytes) */
  ulong remaining = in_len - in_pos;

  if( remaining == 1 ) {
    /* 1 byte remaining → 2 Base64 chars + "==" */
    uint b0 = in[in_pos];
    out[out_pos++] = base64_table[(b0 >> 2) & 0x3F];
    out[out_pos++] = base64_table[(b0 << 4) & 0x3F];
    out[out_pos++] = '=';
    out[out_pos++] = '=';

  } else if( remaining == 2 ) {
    /* 2 bytes remaining → 3 Base64 chars + "=" */
    uint b0 = in[in_pos++];
    uint b1 = in[in_pos];
    out[out_pos++] = base64_table[(b0 >> 2) & 0x3F];
    out[out_pos++] = base64_table[((b0 << 4) | (b1 >> 4)) & 0x3F];
    out[out_pos++] = base64_table[(b1 << 2) & 0x3F];
    out[out_pos++] = '=';
  }

  /* No null terminator added - caller must handle if needed */
  return out_pos;
}
