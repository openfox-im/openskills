/* at_tos_hash_v1.c - TOS Hash V1 implementation
   Aligned to tos-hash/src/v1.rs. */

#include "at/crypto/at_tos_hash_v1.h"

#define AT_TOS_HASH_V1_KECCAK_WORDS      (25UL)
#define AT_TOS_HASH_V1_STAGE1_MAX        (AT_TOS_HASH_V1_MEM_WORDS / AT_TOS_HASH_V1_KECCAK_WORDS)
#define AT_TOS_HASH_V1_ITERS             (1UL)
#define AT_TOS_HASH_V1_SLOTS             (256UL)
#define AT_TOS_HASH_V1_SMALL_PAD_WORDS   (AT_TOS_HASH_V1_MEM_WORDS * 2UL)
#define AT_TOS_HASH_V1_SCRATCHPAD_ITERS  (5000UL)
#define AT_TOS_HASH_V1_BUFFER_SIZE       (42UL)

static uchar const AT_TOS_HASH_V1_AES_SBOX[256] = {
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

static void
keccakp12( ulong a[AT_TOS_HASH_V1_KECCAK_WORDS] ) {
  static ulong const rc[12] = {
    0x000000008000808bUL,
    0x800000000000008bUL,
    0x8000000000008089UL,
    0x8000000000008003UL,
    0x8000000000008002UL,
    0x8000000000000080UL,
    0x000000000000800aUL,
    0x800000008000000aUL,
    0x8000000080008081UL,
    0x8000000000008080UL,
    0x0000000080000001UL,
    0x8000000080008008UL
  };
  static uchar const rho[24] = {
    1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44
  };
  static uchar const pi[24] = {
    10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1
  };

  for( ulong round = 0UL; round < 12UL; round++ ) {
    ulong array[5] = {0UL, 0UL, 0UL, 0UL, 0UL};

    for( ulong x = 0UL; x < 5UL; x++ ) {
      for( ulong y = 0UL; y < 25UL; y += 5UL ) array[x] ^= a[x + y];
    }

    for( ulong x = 0UL; x < 5UL; x++ ) {
      ulong t = array[(x + 4UL) % 5UL] ^ rotl64( array[(x + 1UL) % 5UL], 1U );
      for( ulong y = 0UL; y < 25UL; y += 5UL ) a[y + x] ^= t;
    }

    {
      ulong last = a[1];
      for( ulong x = 0UL; x < 24UL; x++ ) {
        ulong tmp = a[pi[x]];
        a[pi[x]] = rotl64( last, rho[x] );
        last = tmp;
      }
    }

    for( ulong y = 0UL; y < 25UL; y += 5UL ) {
      for( ulong x = 0UL; x < 5UL; x++ ) array[x] = a[y + x];
      for( ulong x = 0UL; x < 5UL; x++ ) {
        a[y + x] = array[x] ^ ((~array[(x + 1UL) % 5UL]) & array[(x + 2UL) % 5UL]);
      }
    }

    a[0] ^= rc[round];
  }
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
write_u64_be( uchar * p,
              ulong   v ) {
  p[0] = (uchar)(v >> 56);
  p[1] = (uchar)(v >> 48);
  p[2] = (uchar)(v >> 40);
  p[3] = (uchar)(v >> 32);
  p[4] = (uchar)(v >> 24);
  p[5] = (uchar)(v >> 16);
  p[6] = (uchar)(v >> 8);
  p[7] = (uchar)(v >> 0);
}

static inline uchar
xtime( uchar x ) {
  return (uchar)((x << 1) ^ ((x & 0x80U) ? 0x1bU : 0x00U));
}

static void
aes_single_round_zero_key( uchar block[16] ) {
  uchar s[16];
  uchar t[16];

  for( ulong i = 0; i < 16UL; i++ ) s[i] = AT_TOS_HASH_V1_AES_SBOX[ block[i] ];

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
    t[base + 0UL] = (uchar)(xtime( a0 ) ^ (xtime( a1 ) ^ a1) ^ a2 ^ a3);
    t[base + 1UL] = (uchar)(a0 ^ xtime( a1 ) ^ (xtime( a2 ) ^ a2) ^ a3);
    t[base + 2UL] = (uchar)(a0 ^ a1 ^ xtime( a2 ) ^ (xtime( a3 ) ^ a3));
    t[base + 3UL] = (uchar)((xtime( a0 ) ^ a0) ^ a1 ^ a2 ^ xtime( a3 ));
  }

  at_memcpy( block, t, 16UL );
}

static void
stage1_fill( ulong state[AT_TOS_HASH_V1_KECCAK_WORDS],
             ulong scratch[AT_TOS_HASH_V1_MEM_WORDS] ) {
  for( ulong i = 0UL; i < AT_TOS_HASH_V1_STAGE1_MAX; i++ ) {
    keccakp12( state );
    ulong rand_int = 0UL;
    for( ulong j = 0UL; j < AT_TOS_HASH_V1_KECCAK_WORDS; j++ ) {
      ulong pair_idx = (j + 1UL) % AT_TOS_HASH_V1_KECCAK_WORDS;
      ulong pair_idx2 = (j + 2UL) % AT_TOS_HASH_V1_KECCAK_WORDS;
      ulong a = state[j] ^ rand_int;
      ulong left = state[pair_idx];
      ulong right = state[pair_idx2];
      ulong xorv = left ^ right;
      ulong v = 0UL;
      switch( xorv & 0x3UL ) {
        case 0UL: v = left & right; break;
        case 1UL: v = ~(left & right); break;
        case 2UL: v = ~xorv; break;
        case 3UL: v = xorv; break;
      }
      rand_int = a ^ v;
      scratch[i * AT_TOS_HASH_V1_KECCAK_WORDS + j] = rand_int;
    }
  }

  {
    ulong i = AT_TOS_HASH_V1_STAGE1_MAX;
    keccakp12( state );
    ulong rand_int = 0UL;
    for( ulong j = 0UL; j <= 17UL; j++ ) {
      ulong pair_idx = (j + 1UL) % AT_TOS_HASH_V1_KECCAK_WORDS;
      ulong pair_idx2 = (j + 2UL) % AT_TOS_HASH_V1_KECCAK_WORDS;
      ulong a = state[j] ^ rand_int;
      ulong left = state[pair_idx];
      ulong right = state[pair_idx2];
      ulong xorv = left ^ right;
      ulong v = 0UL;
      switch( xorv & 0x3UL ) {
        case 0UL: v = left & right; break;
        case 1UL: v = ~(left & right); break;
        case 2UL: v = ~xorv; break;
        case 3UL: v = xorv; break;
      }
      rand_int = a ^ v;
      scratch[i * AT_TOS_HASH_V1_KECCAK_WORDS + j] = rand_int;
    }
  }
}

static void
stage2_mix( ulong scratch[AT_TOS_HASH_V1_MEM_WORDS] ) {
  uint * small_pad = (uint *)scratch;
  uint slots[AT_TOS_HASH_V1_SLOTS];
  ushort indices[AT_TOS_HASH_V1_SLOTS];

  at_memcpy( slots,
             &small_pad[AT_TOS_HASH_V1_SMALL_PAD_WORDS - AT_TOS_HASH_V1_SLOTS],
             AT_TOS_HASH_V1_SLOTS * sizeof(uint) );

  for( ulong iter = 0UL; iter < AT_TOS_HASH_V1_ITERS; iter++ ) {
    for( ulong j = 0UL; j < (AT_TOS_HASH_V1_SMALL_PAD_WORDS / AT_TOS_HASH_V1_SLOTS); j++ ) {
      ulong base = j * AT_TOS_HASH_V1_SLOTS;
      uint total_sum = 0U;

      for( ulong k = 0UL; k < AT_TOS_HASH_V1_SLOTS; k++ ) {
        indices[k] = (ushort)k;
        if( (slots[k] >> 31) == 0U ) total_sum = total_sum + small_pad[base + k];
        else                          total_sum = total_sum - small_pad[base + k];
      }

      for( ulong slot_idx = AT_TOS_HASH_V1_SLOTS; slot_idx > 0UL; slot_idx-- ) {
        ulong idx = slot_idx - 1UL;
        ulong index_in_indices = small_pad[base + idx] % (uint)(idx + 1UL);
        ulong index = indices[index_in_indices];
        uint local_sum = total_sum;
        int s1, s2;
        uint pad_value, factor;

        indices[index_in_indices] = indices[idx];

        s1 = (int)(slots[index] >> 31);
        pad_value = small_pad[base + index];
        if( s1 == 0 ) local_sum = local_sum - pad_value;
        else          local_sum = local_sum + pad_value;

        slots[index] = slots[index] + local_sum;
        s2 = (int)(slots[index] >> 31);
        factor = (uint)((-s1) + s2);
        total_sum = total_sum - (2U * pad_value * factor);
      }
    }
  }

  at_memcpy( &small_pad[AT_TOS_HASH_V1_SMALL_PAD_WORDS - AT_TOS_HASH_V1_SLOTS],
             slots,
             AT_TOS_HASH_V1_SLOTS * sizeof(uint) );
}

static void
stage3_finalize( ulong scratch[AT_TOS_HASH_V1_MEM_WORDS],
                 uchar out_hash[AT_TOS_HASH_V1_HASH_SZ] ) {
  ulong addr_a = (scratch[AT_TOS_HASH_V1_MEM_WORDS - 1UL] >> 15) & 0x7fffUL;
  ulong addr_b = scratch[AT_TOS_HASH_V1_MEM_WORDS - 1UL] & 0x7fffUL;
  ulong mem_a[AT_TOS_HASH_V1_BUFFER_SIZE];
  ulong mem_b[AT_TOS_HASH_V1_BUFFER_SIZE];
  uchar final_result[32];

  for( ulong i = 0UL; i < AT_TOS_HASH_V1_BUFFER_SIZE; i++ ) {
    mem_a[i] = scratch[(addr_a + i) % AT_TOS_HASH_V1_MEM_WORDS];
    mem_b[i] = scratch[(addr_b + i) % AT_TOS_HASH_V1_MEM_WORDS];
  }
  at_memset( final_result, 0, sizeof(final_result) );

  for( ulong i = 0UL; i < AT_TOS_HASH_V1_SCRATCHPAD_ITERS; i++ ) {
    ulong mem_a_v = mem_a[i % AT_TOS_HASH_V1_BUFFER_SIZE];
    ulong mem_b_v = mem_b[i % AT_TOS_HASH_V1_BUFFER_SIZE];
    uchar block[16];
    ulong hash1, hash2, result;

    block[0] = (uchar)(mem_b_v >> 0);  block[1] = (uchar)(mem_b_v >> 8);
    block[2] = (uchar)(mem_b_v >> 16); block[3] = (uchar)(mem_b_v >> 24);
    block[4] = (uchar)(mem_b_v >> 32); block[5] = (uchar)(mem_b_v >> 40);
    block[6] = (uchar)(mem_b_v >> 48); block[7] = (uchar)(mem_b_v >> 56);
    block[8] = (uchar)(mem_a_v >> 0);  block[9] = (uchar)(mem_a_v >> 8);
    block[10] = (uchar)(mem_a_v >> 16); block[11] = (uchar)(mem_a_v >> 24);
    block[12] = (uchar)(mem_a_v >> 32); block[13] = (uchar)(mem_a_v >> 40);
    block[14] = (uchar)(mem_a_v >> 48); block[15] = (uchar)(mem_a_v >> 56);

    aes_single_round_zero_key( block );
    hash1 = read_u64_le( block );
    hash2 = mem_a_v ^ mem_b_v;
    result = ~(hash1 ^ hash2);

    for( ulong j = 0UL; j < 32UL; j++ ) {
      ulong a = mem_a[(j + i) % AT_TOS_HASH_V1_BUFFER_SIZE];
      ulong b = mem_b[(j + i) % AT_TOS_HASH_V1_BUFFER_SIZE];
      ulong v = 0UL;

      switch( (result >> (j * 2UL)) & 0xfUL ) {
        case 0UL:  v = rotl64( result, (uint)j ) ^ b; break;
        case 1UL:  v = ~(rotl64( result, (uint)j ) ^ a); break;
        case 2UL:  v = ~(result ^ a); break;
        case 3UL:  v = result ^ b; break;
        case 4UL:  v = result ^ (a + b); break;
        case 5UL:  v = result ^ (a - b); break;
        case 6UL:  v = result ^ (b - a); break;
        case 7UL:  v = result ^ (a * b); break;
        case 8UL:  v = result ^ (a & b); break;
        case 9UL:  v = result ^ (a | b); break;
        case 10UL: v = result ^ (a ^ b); break;
        case 11UL: v = result ^ (a - result); break;
        case 12UL: v = result ^ (b - result); break;
        case 13UL: v = result ^ (a + result); break;
        case 14UL: v = result ^ (result - a); break;
        case 15UL: v = result ^ (result - b); break;
      }
      result = v;
    }

    addr_b = result & 0x7fffUL;
    mem_a[i % AT_TOS_HASH_V1_BUFFER_SIZE] = result;
    mem_b[i % AT_TOS_HASH_V1_BUFFER_SIZE] = scratch[addr_b];
    addr_a = (result >> 15) & 0x7fffUL;
    scratch[addr_a] = result;

    {
      ulong index = AT_TOS_HASH_V1_SCRATCHPAD_ITERS - i - 1UL;
      if( index < 4UL ) write_u64_be( final_result + (index * 8UL), result );
    }
  }

  at_memcpy( out_hash, final_result, 32UL );
}

void
at_tos_hash_v1_scratch_init( at_tos_hash_v1_scratch_t * scratch ) {
  if( !scratch ) return;
  at_memset( scratch->words, 0, sizeof(scratch->words) );
}

int
at_tos_hash_v1_hash( uchar const *              input,
                     ulong                      input_sz,
                     uchar                      out_hash[AT_TOS_HASH_V1_HASH_SZ],
                     at_tos_hash_v1_scratch_t * scratch ) {
  uchar aligned_input[AT_TOS_HASH_V1_INPUT_SZ];
  ulong state[AT_TOS_HASH_V1_KECCAK_WORDS];

  if( !input || !out_hash || !scratch ) return -1;
  if( input_sz > AT_TOS_HASH_V1_INPUT_SZ ) return -1;

  at_memset( aligned_input, 0, sizeof(aligned_input) );
  at_memcpy( aligned_input, input, input_sz );
  for( ulong i = 0UL; i < AT_TOS_HASH_V1_KECCAK_WORDS; i++ ) {
    state[i] = read_u64_le( aligned_input + (8UL * i) );
  }

  stage1_fill( state, scratch->words );
  stage2_mix( scratch->words );
  stage3_finalize( scratch->words, out_hash );
  return 0;
}
