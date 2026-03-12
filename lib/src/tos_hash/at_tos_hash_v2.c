/* at_tos_hash_v2.c - TOS Hash V2 implementation
   Aligned to tos-hash/src/v2.rs. */

#include "at/crypto/at_tos_hash_v2.h"
#include "at/crypto/at_blake3.h"
#include "at/crypto/at_chacha.h"

#define AT_TOS_HASH_V2_CHUNK_SIZE      (32UL)
#define AT_TOS_HASH_V2_NONCE_SIZE      (12UL)
#define AT_TOS_HASH_V2_OUTPUT_BYTES    (AT_TOS_HASH_V2_MEM_WORDS * 8UL)
#define AT_TOS_HASH_V2_ITERS           (3UL)
#define AT_TOS_HASH_V2_BUFFER_WORDS    (AT_TOS_HASH_V2_MEM_WORDS / 2UL)

static uchar const AT_TOS_HASH_V2_AES_KEY[16] = "tos-network-pow1";

static uchar const AT_TOS_HASH_V2_AES_SBOX[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static inline ulong
rotl64( ulong x,
        uint  r ) {
  r &= 63U;
  return (x << r) | (x >> ((64U - r) & 63U));
}

static inline ulong
rotr64( ulong x,
        uint  r ) {
  r &= 63U;
  return (x >> r) | (x << ((64U - r) & 63U));
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

static inline uchar
xtime( uchar x ) {
  return (uchar)((x << 1) ^ ((x & 0x80U) ? 0x1bU : 0x00U));
}

static void
aes_single_round( uchar block[16],
                  uchar const round_key[16] ) {
  uchar s[16];
  uchar t[16];

  for( ulong i = 0; i < 16UL; i++ ) s[i] = AT_TOS_HASH_V2_AES_SBOX[ block[i] ];

  t[ 0] = s[ 0]; t[ 1] = s[ 5]; t[ 2] = s[10]; t[ 3] = s[15];
  t[ 4] = s[ 4]; t[ 5] = s[ 9]; t[ 6] = s[14]; t[ 7] = s[ 3];
  t[ 8] = s[ 8]; t[ 9] = s[13]; t[10] = s[ 2]; t[11] = s[ 7];
  t[12] = s[12]; t[13] = s[ 1]; t[14] = s[ 6]; t[15] = s[11];

  for( ulong c = 0; c < 4UL; c++ ) {
    ulong base = 4UL * c;
    uchar a0 = t[base + 0UL];
    uchar a1 = t[base + 1UL];
    uchar a2 = t[base + 2UL];
    uchar a3 = t[base + 3UL];
    uchar m0 = (uchar)(xtime( a0 ) ^ (xtime( a1 ) ^ a1) ^ a2 ^ a3);
    uchar m1 = (uchar)(a0 ^ xtime( a1 ) ^ (xtime( a2 ) ^ a2) ^ a3);
    uchar m2 = (uchar)(a0 ^ a1 ^ xtime( a2 ) ^ (xtime( a3 ) ^ a3));
    uchar m3 = (uchar)((xtime( a0 ) ^ a0) ^ a1 ^ a2 ^ xtime( a3 ));
    t[base + 0UL] = m0;
    t[base + 1UL] = m1;
    t[base + 2UL] = m2;
    t[base + 3UL] = m3;
  }

  for( ulong i = 0; i < 16UL; i++ ) block[i] = (uchar)(t[i] ^ round_key[i]);
}

static void
chacha8_apply_keystream( uchar const key[32],
                         uchar const nonce[12],
                         uchar *     out,
                         ulong       out_sz ) {
  uchar key_aligned[32] __attribute__((aligned(32)));
  ulong ctr = 0UL;
  at_memcpy( key_aligned, key, 32UL );
  while( out_sz ) {
    uchar block[64] __attribute__((aligned(64)));
    uchar idx_nonce[16] __attribute__((aligned(16)));
    ulong n = (out_sz < 64UL) ? out_sz : 64UL;

    idx_nonce[0] = (uchar)(ctr >> 0);
    idx_nonce[1] = (uchar)(ctr >> 8);
    idx_nonce[2] = (uchar)(ctr >> 16);
    idx_nonce[3] = (uchar)(ctr >> 24);
    at_memcpy( idx_nonce + 4, nonce, 12UL );

    at_chacha8_block( block, key_aligned, idx_nonce );
    at_memcpy( out, block, n );

    out += n;
    out_sz -= n;
    ctr++;
  }
}

static void
stage1_init( uchar const * input,
             ulong         input_sz,
             uchar *       scratch_bytes ) {
  at_memset( scratch_bytes, 0, AT_TOS_HASH_V2_OUTPUT_BYTES );

  uchar input_hash[32];
  uchar nonce[AT_TOS_HASH_V2_NONCE_SIZE];
  at_blake3_hash( input, input_sz, input_hash );
  at_memcpy( nonce, input_hash, AT_TOS_HASH_V2_NONCE_SIZE );

  ulong num_chunks = (input_sz + AT_TOS_HASH_V2_CHUNK_SIZE - 1UL) / AT_TOS_HASH_V2_CHUNK_SIZE;
  ulong output_offset = 0UL;

  for( ulong chunk_idx = 0UL; chunk_idx < num_chunks; chunk_idx++ ) {
    ulong  chunk_off = chunk_idx * AT_TOS_HASH_V2_CHUNK_SIZE;
    ulong  chunk_len = input_sz - chunk_off;
    if( chunk_len > AT_TOS_HASH_V2_CHUNK_SIZE ) chunk_len = AT_TOS_HASH_V2_CHUNK_SIZE;
    uchar  tmp[64];
    ulong  remaining_output_sz, chunks_left, chunk_output_sz, current_output_sz, part_off, nonce_start;
    uchar *part;

    at_memset( tmp, 0, sizeof(tmp) );
    at_memcpy( tmp, input_hash, 32UL );
    at_memcpy( tmp + 32UL, input + chunk_off, chunk_len );
    at_blake3_hash( tmp, sizeof(tmp), input_hash );

    remaining_output_sz = AT_TOS_HASH_V2_OUTPUT_BYTES - output_offset;
    chunks_left = num_chunks - chunk_idx;
    chunk_output_sz = remaining_output_sz / chunks_left;
    current_output_sz = (remaining_output_sz < chunk_output_sz) ? remaining_output_sz : chunk_output_sz;
    part_off = chunk_idx * current_output_sz;
    part = scratch_bytes + part_off;

    chacha8_apply_keystream( input_hash, nonce, part, current_output_sz );
    output_offset += current_output_sz;

    nonce_start = (current_output_sz > AT_TOS_HASH_V2_NONCE_SIZE)
                    ? (current_output_sz - AT_TOS_HASH_V2_NONCE_SIZE)
                    : 0UL;
    at_memcpy( nonce, part + nonce_start, AT_TOS_HASH_V2_NONCE_SIZE );
  }
}

static ulong
isqrt_u64( ulong n ) {
  if( n < 2UL ) return n;

  ulong x = n;
  ulong y = (x + 1UL) >> 1UL;
  while( y < x ) {
    x = y;
    y = (x + (n / x)) >> 1UL;
  }
  return x;
}

static void
stage3_mix( ulong * scratch ) {
  ulong * mem_a = scratch;
  ulong * mem_b = scratch + AT_TOS_HASH_V2_BUFFER_WORDS;
  ulong   addr_a = mem_b[AT_TOS_HASH_V2_BUFFER_WORDS - 1UL];
  ulong   addr_b = mem_a[AT_TOS_HASH_V2_BUFFER_WORDS - 1UL] >> 32;
  ulong   r = 0UL;

  for( ulong i = 0UL; i < AT_TOS_HASH_V2_ITERS; i++ ) {
    ulong index_a = addr_a % AT_TOS_HASH_V2_BUFFER_WORDS;
    ulong index_b = addr_b % AT_TOS_HASH_V2_BUFFER_WORDS;
    ulong mem_a_v = mem_a[index_a];
    ulong mem_b_v = mem_b[index_b];
    uchar block[16];
    ulong hash1, hash2, result;

    write_u64_le( block,      mem_b_v );
    write_u64_le( block + 8UL, mem_a_v );
    aes_single_round( block, AT_TOS_HASH_V2_AES_KEY );

    hash1 = read_u64_le( block );
    hash2 = mem_a_v ^ mem_b_v;
    result = ~(hash1 ^ hash2);

    for( ulong j = 0UL; j < AT_TOS_HASH_V2_BUFFER_WORDS; j++ ) {
      ulong index_aa = result % AT_TOS_HASH_V2_BUFFER_WORDS;
      ulong index_bb = (~rotr64( result, (uint)r )) % AT_TOS_HASH_V2_BUFFER_WORDS;
      ulong a = mem_a[index_aa];
      ulong b = mem_b[index_bb];
      ulong c = (r < AT_TOS_HASH_V2_BUFFER_WORDS) ? mem_a[r] : mem_b[r - AT_TOS_HASH_V2_BUFFER_WORDS];
      uchar branch_idx;
      ulong v = 0UL;

      r = (r < (AT_TOS_HASH_V2_MEM_WORDS - 1UL)) ? (r + 1UL) : 0UL;
      branch_idx = (uchar)(rotl64( result, (uint)c ) & 0x0fUL);

      switch( branch_idx ) {
        case 0:  v = result ^ rotl64( c, (uint)(i * j) ) ^ b; break;
        case 1:  v = result ^ rotr64( c, (uint)(i * j) ) ^ a; break;
        case 2:  v = result ^ a ^ b ^ c; break;
        case 3:  v = result ^ ((a + b) * c); break;
        case 4:  v = result ^ ((b - c) * a); break;
        case 5:  v = result ^ ((c - a) + b); break;
        case 6:  v = result ^ ((a - b) + c); break;
        case 7:  v = result ^ ((b * c) + a); break;
        case 8:  v = result ^ ((c * a) + b); break;
        case 9:  v = result ^ (a * b * c); break;
        case 10: {
          __uint128_t t1 = (((__uint128_t)a) << 64) | b;
          __uint128_t t2 = (c | 1UL);
          v = result ^ (ulong)(t1 % t2);
        } break;
        case 11: {
          __uint128_t t1 = (((__uint128_t)b) << 64) | c;
          __uint128_t t2 = (((__uint128_t)rotl64( result, (uint)r )) << 64) | (a | 2UL);
          v = result ^ (ulong)(t1 % t2);
        } break;
        case 12: {
          __uint128_t t1 = (((__uint128_t)c) << 64) | a;
          __uint128_t t2 = (b | 4UL);
          v = result ^ (ulong)(t1 / t2);
        } break;
        case 13: {
          __uint128_t t1 = (((__uint128_t)rotl64( result, (uint)r )) << 64) | b;
          __uint128_t t2 = (((__uint128_t)a) << 64) | (c | 8UL);
          v = result ^ (ulong)((t1 > t2) ? (t1 / t2) : (a ^ b));
        } break;
        case 14: {
          __uint128_t t1 = (((__uint128_t)b) << 64) | a;
          __uint128_t t2 = c;
          v = result ^ (ulong)((t1 * t2) >> 64);
        } break;
        case 15: {
          __uint128_t t1 = (((__uint128_t)a) << 64) | c;
          __uint128_t t2 = (((__uint128_t)rotr64( result, (uint)r )) << 64) | b;
          v = result ^ (ulong)((t1 * t2) >> 64);
        } break;
      }

      result = rotl64( v, 1U );

      {
        ulong t = mem_a[AT_TOS_HASH_V2_BUFFER_WORDS - j - 1UL] ^ result;
        mem_a[AT_TOS_HASH_V2_BUFFER_WORDS - j - 1UL] = t;
        mem_b[j] ^= rotr64( t, (uint)result );
      }
    }

    addr_a = result;
    addr_b = isqrt_u64( result );
  }
}

void
at_tos_hash_v2_scratch_init( at_tos_hash_v2_scratch_t * scratch ) {
  if( !scratch ) return;
  at_memset( scratch->words, 0, sizeof(scratch->words) );
}

int
at_tos_hash_v2_hash( uchar const *              input,
                     ulong                      input_sz,
                     uchar                      out_hash[AT_TOS_HASH_V2_HASH_SZ],
                     at_tos_hash_v2_scratch_t * scratch ) {
  uchar * scratch_bytes;

  if( !input || !out_hash || !scratch ) return -1;

  scratch_bytes = (uchar *)scratch->words;
  stage1_init( input, input_sz, scratch_bytes );
  stage3_mix( scratch->words );
  at_blake3_hash( scratch_bytes, AT_TOS_HASH_V2_OUTPUT_BYTES, out_hash );
  return 0;
}
