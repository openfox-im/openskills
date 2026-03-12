/* Avatar SHA1 implementation for WebSocket handshake.

   Based on RFC 3174 specification.

   SECURITY NOTE: SHA1 is cryptographically broken. This implementation is
   ONLY for WebSocket protocol compliance (RFC 6455 requires SHA1). */

#include "at/crypto/at_sha1.h"
#include "at/infra/at_util.h"

/* SHA1 constants */
#define AT_SHA1_BLOCK_SIZE  64UL
#define AT_SHA1_HASH_SIZE   20UL

/* SHA1 round constants */
#define K0 0x5A827999UL  /* 0 <= t <= 19 */
#define K1 0x6ED9EBA1UL  /* 20 <= t <= 39 */
#define K2 0x8F1BBCDCUL  /* 40 <= t <= 59 */
#define K3 0xCA62C1D6UL  /* 60 <= t <= 79 */

/* SHA1 initial hash values (big-endian) */
#define H0_INIT 0x67452301UL
#define H1_INIT 0xEFCDAB89UL
#define H2_INIT 0x98BADCFEUL
#define H3_INIT 0x10325476UL
#define H4_INIT 0xC3D2E1F0UL

/* Rotate left macro */
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* SHA1 round functions */
#define F0(b, c, d) (((b) & (c)) | ((~(b)) & (d)))           /* Ch */
#define F1(b, c, d) ((b) ^ (c) ^ (d))                         /* Parity */
#define F2(b, c, d) (((b) & (c)) | ((b) & (d)) | ((c) & (d))) /* Maj */
#define F3(b, c, d) ((b) ^ (c) ^ (d))                         /* Parity */

/* Read 32-bit big-endian value from byte array */
static inline uint
read_be32( uchar const * p ) {
  return ((uint)p[0] << 24) |
         ((uint)p[1] << 16) |
         ((uint)p[2] << 8)  |
         ((uint)p[3]);
}

/* Write 32-bit big-endian value to byte array */
static inline void
write_be32( uchar * p, uint val ) {
  p[0] = (uchar)(val >> 24);
  p[1] = (uchar)(val >> 16);
  p[2] = (uchar)(val >> 8);
  p[3] = (uchar)(val);
}

/* Process one 512-bit (64-byte) block */
static void
sha1_process_block( uint         state[5],
                    uchar const  block[64] ) {
  uint W[80];
  uint a, b, c, d, e, temp;
  uint t;

  /* Prepare message schedule (80 words) */
  for( t = 0; t < 16; t++ ) {
    W[t] = read_be32( block + t * 4 );
  }
  for( t = 16; t < 80; t++ ) {
    W[t] = ROTL( W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1 );
  }

  /* Initialize working variables */
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
  e = state[4];

  /* 80 rounds */
  for( t = 0; t < 20; t++ ) {
    temp = ROTL(a, 5) + F0(b, c, d) + e + W[t] + K0;
    e = d;
    d = c;
    c = ROTL(b, 30);
    b = a;
    a = temp;
  }
  for( t = 20; t < 40; t++ ) {
    temp = ROTL(a, 5) + F1(b, c, d) + e + W[t] + K1;
    e = d;
    d = c;
    c = ROTL(b, 30);
    b = a;
    a = temp;
  }
  for( t = 40; t < 60; t++ ) {
    temp = ROTL(a, 5) + F2(b, c, d) + e + W[t] + K2;
    e = d;
    d = c;
    c = ROTL(b, 30);
    b = a;
    a = temp;
  }
  for( t = 60; t < 80; t++ ) {
    temp = ROTL(a, 5) + F3(b, c, d) + e + W[t] + K3;
    e = d;
    d = c;
    c = ROTL(b, 30);
    b = a;
    a = temp;
  }

  /* Add working variables to state */
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
}

void
at_sha1_hash( uchar const * data,
              ulong         data_len,
              uchar         out[20] ) {
  uint state[5];
  ulong processed = 0;
  uchar block[AT_SHA1_BLOCK_SIZE];

  /* Initialize state with SHA1 IV */
  state[0] = H0_INIT;
  state[1] = H1_INIT;
  state[2] = H2_INIT;
  state[3] = H3_INIT;
  state[4] = H4_INIT;

  /* Process complete 64-byte blocks */
  while( processed + AT_SHA1_BLOCK_SIZE <= data_len ) {
    sha1_process_block( state, data + processed );
    processed += AT_SHA1_BLOCK_SIZE;
  }

  /* Process final block with padding */
  ulong remaining = data_len - processed;
  at_memset( block, 0, AT_SHA1_BLOCK_SIZE );
  if( remaining > 0 ) {
    at_memcpy( block, data + processed, remaining );
  }

  /* Append padding bit (0x80) */
  block[remaining] = 0x80;

  /* If not enough room for length (8 bytes), process block and start new one */
  if( remaining >= 56 ) {
    sha1_process_block( state, block );
    at_memset( block, 0, AT_SHA1_BLOCK_SIZE );
  }

  /* Append message length in bits (big-endian 64-bit) */
  ulong bit_len = data_len * 8;
  write_be32( block + 56, (uint)(bit_len >> 32) );  /* High 32 bits */
  write_be32( block + 60, (uint)(bit_len) );        /* Low 32 bits */

  /* Process final block */
  sha1_process_block( state, block );

  /* Convert state to output bytes (big-endian) */
  write_be32( out + 0,  state[0] );
  write_be32( out + 4,  state[1] );
  write_be32( out + 8,  state[2] );
  write_be32( out + 12, state[3] );
  write_be32( out + 16, state[4] );
}
