/* at_ripemd160.c - RIPEMD-160 hash implementation (ISO/IEC 10118-3)

   RIPEMD-160 produces a 160-bit (20-byte) hash digest using a
   Merkle-Damgard construction with two parallel computation streams
   (left and right) that use different round constants and rotation amounts.

   The output is left-padded to 32 bytes (EVM precompile 0x03 convention):
   12 zero bytes followed by the 20-byte digest. */

#include "at_ripemd160.h"
#include "at/infra/at_util.h"

/* Initial hash values (little-endian) */
#define AT_RIPEMD160_H0 (0x67452301UL)
#define AT_RIPEMD160_H1 (0xEFCDAB89UL)
#define AT_RIPEMD160_H2 (0x98BADCFEUL)
#define AT_RIPEMD160_H3 (0x10325476UL)
#define AT_RIPEMD160_H4 (0xC3D2E1F0UL)

/* Left-stream round constants */
#define AT_RMD_KL0 (0x00000000UL)
#define AT_RMD_KL1 (0x5A827999UL)
#define AT_RMD_KL2 (0x6ED9EBA1UL)
#define AT_RMD_KL3 (0x8F1BBCDCUL)
#define AT_RMD_KL4 (0xA953FD4EUL)

/* Right-stream round constants */
#define AT_RMD_KR0 (0x50A28BE6UL)
#define AT_RMD_KR1 (0x5C4DD124UL)
#define AT_RMD_KR2 (0x6D703EF3UL)
#define AT_RMD_KR3 (0x7A6D76E9UL)
#define AT_RMD_KR4 (0x00000000UL)

/* 32-bit left rotation */
static inline uint
rmd_rol( uint x, uint n ) {
  return (x << n) | (x >> (32U - n));
}

/* Boolean functions */
static inline uint rmd_f0( uint x, uint y, uint z ) { return x ^ y ^ z; }
static inline uint rmd_f1( uint x, uint y, uint z ) { return (x & y) | (~x & z); }
static inline uint rmd_f2( uint x, uint y, uint z ) { return (x | ~y) ^ z; }
static inline uint rmd_f3( uint x, uint y, uint z ) { return (x & z) | (y & ~z); }
static inline uint rmd_f4( uint x, uint y, uint z ) { return x ^ (y | ~z); }

/* Message word selection for left stream */
static uint const rmd_rl[80] = {
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,  /* round 0 */
   7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,  /* round 1 */
   3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,  /* round 2 */
   1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,  /* round 3 */
   4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13   /* round 4 */
};

/* Message word selection for right stream */
static uint const rmd_rr[80] = {
   5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,  /* round 0 */
   6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,  /* round 1 */
  15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,  /* round 2 */
   8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,  /* round 3 */
  12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11   /* round 4 */
};

/* Left-stream rotation amounts */
static uint const rmd_sl[80] = {
  11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,  /* round 0 */
   7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,  /* round 1 */
  11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,  /* round 2 */
  11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,  /* round 3 */
   9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6   /* round 4 */
};

/* Right-stream rotation amounts */
static uint const rmd_sr[80] = {
   8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,  /* round 0 */
   9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,  /* round 1 */
   9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,  /* round 2 */
  15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,  /* round 3 */
   8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11   /* round 4 */
};

/* Load a 32-bit little-endian word from a byte array */
static inline uint
rmd_load_le32( uchar const * p ) {
  return (uint)p[0] | ((uint)p[1] << 8) | ((uint)p[2] << 16) | ((uint)p[3] << 24);
}

/* Store a 32-bit little-endian word to a byte array */
static inline void
rmd_store_le32( uchar * p, uint v ) {
  p[0] = (uchar)( v        & 0xFFU );
  p[1] = (uchar)( (v >> 8) & 0xFFU );
  p[2] = (uchar)( (v >>16) & 0xFFU );
  p[3] = (uchar)( (v >>24) & 0xFFU );
}

/* Compress one 64-byte block */
static void
rmd_compress( uint * h, uchar const * block ) {
  /* Load message words */
  uint x[16];
  for( uint i = 0; i < 16U; i++ ) {
    x[i] = rmd_load_le32( block + i * 4U );
  }

  uint al = h[0], bl = h[1], cl = h[2], dl = h[3], el = h[4];
  uint ar = h[0], br = h[1], cr = h[2], dr = h[3], er = h[4];

  for( uint j = 0; j < 80U; j++ ) {
    uint fl, kl, fr, kr;

    /* Select boolean function and constant per round */
    if( j < 16U ) {
      fl = rmd_f0( bl, cl, dl ); kl = AT_RMD_KL0;
      fr = rmd_f4( br, cr, dr ); kr = AT_RMD_KR0;
    } else if( j < 32U ) {
      fl = rmd_f1( bl, cl, dl ); kl = AT_RMD_KL1;
      fr = rmd_f3( br, cr, dr ); kr = AT_RMD_KR1;
    } else if( j < 48U ) {
      fl = rmd_f2( bl, cl, dl ); kl = AT_RMD_KL2;
      fr = rmd_f2( br, cr, dr ); kr = AT_RMD_KR2;
    } else if( j < 64U ) {
      fl = rmd_f3( bl, cl, dl ); kl = AT_RMD_KL3;
      fr = rmd_f1( br, cr, dr ); kr = AT_RMD_KR3;
    } else {
      fl = rmd_f4( bl, cl, dl ); kl = AT_RMD_KL4;
      fr = rmd_f0( br, cr, dr ); kr = AT_RMD_KR4;
    }

    /* Left stream */
    uint tl = al + fl + x[ rmd_rl[j] ] + kl;
    tl = rmd_rol( tl, rmd_sl[j] ) + el;
    al = el;
    el = dl;
    dl = rmd_rol( cl, 10U );
    cl = bl;
    bl = tl;

    /* Right stream */
    uint tr = ar + fr + x[ rmd_rr[j] ] + kr;
    tr = rmd_rol( tr, rmd_sr[j] ) + er;
    ar = er;
    er = dr;
    dr = rmd_rol( cr, 10U );
    cr = br;
    br = tr;
  }

  /* Final addition */
  uint t  = h[1] + cl + dr;
  h[1] = h[2] + dl + er;
  h[2] = h[3] + el + ar;
  h[3] = h[4] + al + br;
  h[4] = h[0] + bl + cr;
  h[0] = t;
}

void *
at_ripemd160_hash( void const * data,
                   ulong        data_sz,
                   void *       out32 ) {
  uchar const * src = (uchar const *)data;
  uchar *       dst = (uchar *)out32;

  /* Initialize state */
  uint h[5];
  h[0] = (uint)AT_RIPEMD160_H0;
  h[1] = (uint)AT_RIPEMD160_H1;
  h[2] = (uint)AT_RIPEMD160_H2;
  h[3] = (uint)AT_RIPEMD160_H3;
  h[4] = (uint)AT_RIPEMD160_H4;

  /* Process complete 64-byte blocks */
  ulong remaining = data_sz;
  while( remaining >= 64UL ) {
    rmd_compress( h, src );
    src       += 64;
    remaining -= 64UL;
  }

  /* Final block with MD-padding */
  uchar pad[128];
  at_memset( pad, 0, 128 );
  if( remaining > 0UL ) {
    at_memcpy( pad, src, remaining );
  }
  pad[ remaining ] = 0x80;

  /* If remaining >= 56, we need two blocks */
  ulong pad_blocks;
  if( remaining >= 56UL ) {
    pad_blocks = 2UL;
  } else {
    pad_blocks = 1UL;
  }

  /* Append 64-bit little-endian bit count at end of last block */
  ulong bit_count = data_sz * 8UL;
  ulong len_offset = (pad_blocks * 64UL) - 8UL;
  pad[ len_offset     ] = (uchar)( bit_count         & 0xFFUL );
  pad[ len_offset + 1 ] = (uchar)( (bit_count >>  8) & 0xFFUL );
  pad[ len_offset + 2 ] = (uchar)( (bit_count >> 16) & 0xFFUL );
  pad[ len_offset + 3 ] = (uchar)( (bit_count >> 24) & 0xFFUL );
  pad[ len_offset + 4 ] = (uchar)( (bit_count >> 32) & 0xFFUL );
  pad[ len_offset + 5 ] = (uchar)( (bit_count >> 40) & 0xFFUL );
  pad[ len_offset + 6 ] = (uchar)( (bit_count >> 48) & 0xFFUL );
  pad[ len_offset + 7 ] = (uchar)( (bit_count >> 56) & 0xFFUL );

  /* Compress padding block(s) */
  rmd_compress( h, pad );
  if( pad_blocks == 2UL ) {
    rmd_compress( h, pad + 64 );
  }

  /* Write 32-byte output: 12 zero bytes + 20-byte digest (EVM convention) */
  at_memset( dst, 0, 12 );
  for( uint i = 0; i < 5U; i++ ) {
    rmd_store_le32( dst + 12 + i * 4U, h[i] );
  }

  return out32;
}
