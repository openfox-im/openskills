/* at_blake2b.c - BLAKE2b-F compression function (RFC 7693 / EIP-152)

   Implements the core compression function F of BLAKE2b.
   This is not a full BLAKE2b hash; it only exposes the compression
   primitive as required by EVM precompile 0x09. */

#include "at_blake2b.h"
#include "at/infra/at_util.h"

/* BLAKE2b IV (first 8 fractional digits of pi as uint64) */
static ulong const blake2b_iv[8] = {
  0x6A09E667F3BCC908UL, 0xBB67AE8584CAA73BUL,
  0x3C6EF372FE94F82BUL, 0xA54FF53A5F1D36F1UL,
  0x510E527FADE682D1UL, 0x9B05688C2B3E6C1FUL,
  0x1F83D9ABFB41BD6BUL, 0x5BE0CD19137E2179UL
};

/* BLAKE2b sigma permutation table (10 rounds, then repeats) */
static uchar const blake2b_sigma[10][16] = {
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 }
};

/* 64-bit right rotation */
static inline ulong
b2b_rotr64( ulong x, uint n ) {
  return (x >> n) | (x << (64U - n));
}

/* Load a 64-bit little-endian value */
static inline ulong
b2b_load_le64( uchar const * p ) {
  return (ulong)p[0]       | ((ulong)p[1] <<  8) |
         ((ulong)p[2] << 16) | ((ulong)p[3] << 24) |
         ((ulong)p[4] << 32) | ((ulong)p[5] << 40) |
         ((ulong)p[6] << 48) | ((ulong)p[7] << 56);
}

/* Store a 64-bit little-endian value */
static inline void
b2b_store_le64( uchar * p, ulong v ) {
  p[0] = (uchar)( v        & 0xFFUL );
  p[1] = (uchar)( (v >> 8) & 0xFFUL );
  p[2] = (uchar)( (v >>16) & 0xFFUL );
  p[3] = (uchar)( (v >>24) & 0xFFUL );
  p[4] = (uchar)( (v >>32) & 0xFFUL );
  p[5] = (uchar)( (v >>40) & 0xFFUL );
  p[6] = (uchar)( (v >>48) & 0xFFUL );
  p[7] = (uchar)( (v >>56) & 0xFFUL );
}

/* BLAKE2b G mixing function */
#define B2B_G( v, a, b, c, d, x, y )  \
  do {                                  \
    v[a] = v[a] + v[b] + (x);          \
    v[d] = b2b_rotr64( v[d] ^ v[a], 32U ); \
    v[c] = v[c] + v[d];                \
    v[b] = b2b_rotr64( v[b] ^ v[c], 24U ); \
    v[a] = v[a] + v[b] + (y);          \
    v[d] = b2b_rotr64( v[d] ^ v[a], 16U ); \
    v[c] = v[c] + v[d];                \
    v[b] = b2b_rotr64( v[b] ^ v[c], 63U ); \
  } while(0)

void
at_blake2b_compress( uchar *       h_out,
                     uint          rounds,
                     uchar const * h,
                     uchar const * m,
                     ulong         t0,
                     ulong         t1,
                     uchar         f ) {
  /* Load state and message */
  ulong hv[8];
  ulong mv[16];
  for( uint i = 0; i < 8U; i++ ) {
    hv[i] = b2b_load_le64( h + i * 8U );
  }
  for( uint i = 0; i < 16U; i++ ) {
    mv[i] = b2b_load_le64( m + i * 8U );
  }

  /* Initialize working vector v[0..15] */
  ulong v[16];
  v[ 0] = hv[0];  v[ 1] = hv[1];  v[ 2] = hv[2];  v[ 3] = hv[3];
  v[ 4] = hv[4];  v[ 5] = hv[5];  v[ 6] = hv[6];  v[ 7] = hv[7];
  v[ 8] = blake2b_iv[0];  v[ 9] = blake2b_iv[1];
  v[10] = blake2b_iv[2];  v[11] = blake2b_iv[3];
  v[12] = blake2b_iv[4] ^ t0;
  v[13] = blake2b_iv[5] ^ t1;
  v[14] = f ? (blake2b_iv[6] ^ 0xFFFFFFFFFFFFFFFFUL) : blake2b_iv[6];
  v[15] = blake2b_iv[7];

  /* Execute rounds (sigma table repeats every 10 rounds) */
  for( uint r = 0; r < rounds; r++ ) {
    uchar const * s = blake2b_sigma[ r % 10U ];

    B2B_G( v, 0, 4,  8, 12, mv[s[ 0]], mv[s[ 1]] );
    B2B_G( v, 1, 5,  9, 13, mv[s[ 2]], mv[s[ 3]] );
    B2B_G( v, 2, 6, 10, 14, mv[s[ 4]], mv[s[ 5]] );
    B2B_G( v, 3, 7, 11, 15, mv[s[ 6]], mv[s[ 7]] );
    B2B_G( v, 0, 5, 10, 15, mv[s[ 8]], mv[s[ 9]] );
    B2B_G( v, 1, 6, 11, 12, mv[s[10]], mv[s[11]] );
    B2B_G( v, 2, 7,  8, 13, mv[s[12]], mv[s[13]] );
    B2B_G( v, 3, 4,  9, 14, mv[s[14]], mv[s[15]] );
  }

  /* Finalize: h'[i] = h[i] ^ v[i] ^ v[i+8] */
  for( uint i = 0; i < 8U; i++ ) {
    hv[i] ^= v[i] ^ v[i + 8U];
  }

  /* Write output as 64 bytes LE */
  for( uint i = 0; i < 8U; i++ ) {
    b2b_store_le64( h_out + i * 8U, hv[i] );
  }
}
