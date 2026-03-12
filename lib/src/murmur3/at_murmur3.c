/* at_murmur3.c - Murmur3 hash implementation
   MurmurHash3 implementation for TBPF syscall dispatch */

#include "at/crypto/murmur3/at_murmur3.h"

AT_FN_PURE uint
at_murmur3_32( void const * data,
               ulong        sz,
               uint         seed ) {
  uchar const * p   = (uchar const *)data;
  uchar const * end = p + (sz & ~3UL);

  uint h = seed;

  /* Process 4-byte chunks */
  while( p < end ) {
    uint k;
    at_memcpy( &k, p, sizeof(uint) );
    p += 4;

    k *= 0xcc9e2d51U;
    k  = at_uint_rotate_left( k, 15 );
    k *= 0x1b873593U;

    h ^= k;
    h  = at_uint_rotate_left( h, 13 );
    h  = h * 5U + 0xe6546b64U;
  }

  /* Process remaining bytes */
  uint k = 0U;
  switch( sz & 3UL ) {
    case 3: k ^= (uint)p[2] << 16; __attribute__((fallthrough));
    case 2: k ^= (uint)p[1] << 8;  __attribute__((fallthrough));
    case 1: k ^= (uint)p[0];
            k *= 0xcc9e2d51U;
            k  = at_uint_rotate_left( k, 15 );
            k *= 0x1b873593U;
            h ^= k;
  }

  /* Finalization */
  h ^= (uint)sz;
  h ^= h >> 16;
  h *= 0x85ebca6bU;
  h ^= h >> 13;
  h *= 0xc2b2ae35U;
  h ^= h >> 16;

  return h;
}