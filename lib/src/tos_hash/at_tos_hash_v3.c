/* at_tos_hash_v3.c - TOS Hash V3 implementation
   Ported from tos-hash C/thash_v3.c and aligned to Rust src/v3.rs. */

#include "at/crypto/at_tos_hash_v3.h"
#include "at/crypto/at_blake3.h"

static ulong const AT_TOS_HASH_V3_STRIDES[4] = { 1UL, 64UL, 256UL, 1024UL };
static ulong const AT_TOS_HASH_V3_MIX_CONST  = 0x517cc1b727220a95UL;

static inline ulong
rotl64( ulong x,
        ulong r ) {
  r &= 63UL;
  return (x << r) | (x >> ((64UL - r) & 63UL));
}

static inline ulong
rotr64( ulong x,
        ulong r ) {
  r &= 63UL;
  return (x >> r) | (x << ((64UL - r) & 63UL));
}

static inline ulong
mix( ulong a,
     ulong b,
     ulong round ) {
  ulong rot = (round * 7UL) % 64UL;
  ulong x = a + b;
  ulong y = a ^ rotl64( b, rot );
  ulong z = x * AT_TOS_HASH_V3_MIX_CONST;
  return z ^ rotr64( y, rot / 2UL );
}

static inline ulong
read_u64_le( uchar const * p ) {
  return
      ((ulong)p[0] << 0)
    | ((ulong)p[1] << 8)
    | ((ulong)p[2] << 16)
    | ((ulong)p[3] << 24)
    | ((ulong)p[4] << 32)
    | ((ulong)p[5] << 40)
    | ((ulong)p[6] << 48)
    | ((ulong)p[7] << 56);
}

static inline void
write_u64_le( uchar * p,
              ulong   v ) {
  p[0] = (uchar)(v >> 0);
  p[1] = (uchar)(v >> 8);
  p[2] = (uchar)(v >> 16);
  p[3] = (uchar)(v >> 24);
  p[4] = (uchar)(v >> 32);
  p[5] = (uchar)(v >> 40);
  p[6] = (uchar)(v >> 48);
  p[7] = (uchar)(v >> 56);
}

static void
stage1_init( uchar const * input,
             ulong         input_sz,
             ulong *       scratch ) {
  uchar hash[32];
  at_blake3_hash( input, input_sz, hash );

  ulong state[4];
  state[0] = read_u64_le( hash + 0 );
  state[1] = read_u64_le( hash + 8 );
  state[2] = read_u64_le( hash + 16 );
  state[3] = read_u64_le( hash + 24 );

  for( ulong i = 0UL; i < AT_TOS_HASH_V3_MEM_WORDS; i++ ) {
    ulong idx = i & 3UL;
    state[idx] = mix( state[idx], state[(idx + 1UL) & 3UL], i );
    scratch[i] = state[idx];
  }
}

static void
stage2_mix( ulong * scratch ) {
  for( ulong pass = 0UL; pass < AT_TOS_HASH_V3_MEM_PASSES; pass++ ) {
    if( (pass & 1UL) == 0UL ) {
      ulong carry = scratch[AT_TOS_HASH_V3_MEM_WORDS - 1UL];
      for( ulong i = 0UL; i < AT_TOS_HASH_V3_MEM_WORDS; i++ ) {
        ulong prev = i ? scratch[i - 1UL] : scratch[AT_TOS_HASH_V3_MEM_WORDS - 1UL];
        scratch[i] = mix( scratch[i], prev ^ carry, pass );
        carry = scratch[i];
      }
    } else {
      ulong carry = scratch[0];
      for( ulong i = AT_TOS_HASH_V3_MEM_WORDS; i > 0UL; i-- ) {
        ulong idx = i - 1UL;
        ulong next = (idx + 1UL < AT_TOS_HASH_V3_MEM_WORDS) ? scratch[idx + 1UL] : scratch[0];
        scratch[idx] = mix( scratch[idx], next ^ carry, pass );
        carry = scratch[idx];
      }
    }
  }
}

static void
stage3_strided( ulong * scratch ) {
  for( ulong round = 0UL; round < AT_TOS_HASH_V3_MIX_ROUNDS; round++ ) {
    ulong stride = AT_TOS_HASH_V3_STRIDES[ round & 3UL ];
    for( ulong i = 0UL; i < AT_TOS_HASH_V3_MEM_WORDS; i++ ) {
      ulong j = (i + stride) % AT_TOS_HASH_V3_MEM_WORDS;
      ulong k = (i + stride * 2UL) % AT_TOS_HASH_V3_MEM_WORDS;
      ulong a = scratch[i];
      ulong b = scratch[j];
      ulong c = scratch[k];
      scratch[i] = mix( a, b ^ c, round );
    }
  }
}

static void
stage4_finalize( ulong const * scratch,
                 uchar         out_hash[32] ) {
  ulong folded[4] = { 0UL, 0UL, 0UL, 0UL };
  for( ulong i = 0UL; i < AT_TOS_HASH_V3_MEM_WORDS; i++ ) {
    folded[i & 3UL] ^= scratch[i];
  }

  uchar bytes[32];
  write_u64_le( bytes + 0, folded[0] );
  write_u64_le( bytes + 8, folded[1] );
  write_u64_le( bytes + 16, folded[2] );
  write_u64_le( bytes + 24, folded[3] );

  at_blake3_hash( bytes, sizeof(bytes), out_hash );
}

void
at_tos_hash_v3_scratch_init( at_tos_hash_v3_scratch_t * scratch ) {
  if( !scratch ) return;
  at_memset( scratch->words, 0, sizeof(scratch->words) );
}

int
at_tos_hash_v3_hash( uchar const *              input,
                     ulong                      input_sz,
                     uchar                      out_hash[AT_TOS_HASH_V3_HASH_SZ],
                     at_tos_hash_v3_scratch_t * scratch ) {
  if( !input || !out_hash || !scratch ) return -1;

  stage1_init( input, input_sz, scratch->words );
  stage2_mix( scratch->words );
  stage3_strided( scratch->words );
  stage4_finalize( scratch->words, out_hash );
  return 0;
}
