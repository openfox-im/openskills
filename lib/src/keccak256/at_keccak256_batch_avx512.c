/* Keccak256 AVX-512 Batch Implementation

   This file implements parallel Keccak256 hashing using AVX-512.
   Up to 8 independent messages are processed simultaneously. */

#include "at_keccak256.h"
#include "at/infra/at_util.h"
#include "at_keccak256_private.h"

#if AT_KECCAK256_BATCH_IMPL==2

#include "at/infra/simd/at_avx512.h"

/* Process 8 Keccak-f[1600] permutations in parallel using AVX-512 */
static void
keccak_f1600_x8( ulong state[8][25] ) {

  static ulong const rc[24] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL,
    0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008AUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
    0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL, 0x800000008000000AUL,
    0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
  };

  wwl_t s[25];
  for( int i = 0; i < 25; i++ ) {
    s[i] = wwl( (long)state[0][i], (long)state[1][i], (long)state[2][i], (long)state[3][i],
                (long)state[4][i], (long)state[5][i], (long)state[6][i], (long)state[7][i] );
  }

  for( int round = 0; round < 24; round++ ) {

    wwl_t c[5];
    c[0] = wwl_xor( wwl_xor( wwl_xor( s[0], s[5] ), wwl_xor( s[10], s[15] ) ), s[20] );
    c[1] = wwl_xor( wwl_xor( wwl_xor( s[1], s[6] ), wwl_xor( s[11], s[16] ) ), s[21] );
    c[2] = wwl_xor( wwl_xor( wwl_xor( s[2], s[7] ), wwl_xor( s[12], s[17] ) ), s[22] );
    c[3] = wwl_xor( wwl_xor( wwl_xor( s[3], s[8] ), wwl_xor( s[13], s[18] ) ), s[23] );
    c[4] = wwl_xor( wwl_xor( wwl_xor( s[4], s[9] ), wwl_xor( s[14], s[19] ) ), s[24] );

    wwl_t d[5];
    d[0] = wwl_xor( c[4], wwl_rol( c[1], 1 ) );
    d[1] = wwl_xor( c[0], wwl_rol( c[2], 1 ) );
    d[2] = wwl_xor( c[1], wwl_rol( c[3], 1 ) );
    d[3] = wwl_xor( c[2], wwl_rol( c[4], 1 ) );
    d[4] = wwl_xor( c[3], wwl_rol( c[0], 1 ) );

    for( int y = 0; y < 5; y++ ) {
      s[0 + 5*y] = wwl_xor( s[0 + 5*y], d[0] );
      s[1 + 5*y] = wwl_xor( s[1 + 5*y], d[1] );
      s[2 + 5*y] = wwl_xor( s[2 + 5*y], d[2] );
      s[3 + 5*y] = wwl_xor( s[3 + 5*y], d[3] );
      s[4 + 5*y] = wwl_xor( s[4 + 5*y], d[4] );
    }

    wwl_t b[25];
    b[ 0] = s[ 0];
    b[ 1] = wwl_rol( s[ 6], 44 );
    b[ 2] = wwl_rol( s[12], 43 );
    b[ 3] = wwl_rol( s[18], 21 );
    b[ 4] = wwl_rol( s[24], 14 );

    b[ 5] = wwl_rol( s[ 3], 28 );
    b[ 6] = wwl_rol( s[ 9], 20 );
    b[ 7] = wwl_rol( s[10],  3 );
    b[ 8] = wwl_rol( s[16], 45 );
    b[ 9] = wwl_rol( s[22], 61 );

    b[10] = wwl_rol( s[ 1],  1 );
    b[11] = wwl_rol( s[ 7],  6 );
    b[12] = wwl_rol( s[13], 25 );
    b[13] = wwl_rol( s[19],  8 );
    b[14] = wwl_rol( s[20], 18 );

    b[15] = wwl_rol( s[ 4], 27 );
    b[16] = wwl_rol( s[ 5], 36 );
    b[17] = wwl_rol( s[11], 10 );
    b[18] = wwl_rol( s[17], 15 );
    b[19] = wwl_rol( s[23], 56 );

    b[20] = wwl_rol( s[ 2], 62 );
    b[21] = wwl_rol( s[ 8], 55 );
    b[22] = wwl_rol( s[14], 39 );
    b[23] = wwl_rol( s[15], 41 );
    b[24] = wwl_rol( s[21],  2 );

    for( int y = 0; y < 5; y++ ) {
      wwl_t t0 = b[0 + 5*y];
      wwl_t t1 = b[1 + 5*y];
      wwl_t t2 = b[2 + 5*y];
      wwl_t t3 = b[3 + 5*y];
      wwl_t t4 = b[4 + 5*y];

      s[0 + 5*y] = wwl_xor( t0, wwl_andnot( t1, t2 ) );
      s[1 + 5*y] = wwl_xor( t1, wwl_andnot( t2, t3 ) );
      s[2 + 5*y] = wwl_xor( t2, wwl_andnot( t3, t4 ) );
      s[3 + 5*y] = wwl_xor( t3, wwl_andnot( t4, t0 ) );
      s[4 + 5*y] = wwl_xor( t4, wwl_andnot( t0, t1 ) );
    }

    s[0] = wwl_xor( s[0], wwl_bcast( (long)rc[round] ) );
  }

  for( int i = 0; i < 25; i++ ) {
    long tmp[8] WW_ATTR;
    wwl_st( tmp, s[i] );
    state[0][i] = (ulong)tmp[0];
    state[1][i] = (ulong)tmp[1];
    state[2][i] = (ulong)tmp[2];
    state[3][i] = (ulong)tmp[3];
    state[4][i] = (ulong)tmp[4];
    state[5][i] = (ulong)tmp[5];
    state[6][i] = (ulong)tmp[6];
    state[7][i] = (ulong)tmp[7];
  }
}

void *
at_keccak256_batch_fini_avx512( at_keccak256_batch_t * batch ) {
  ulong cnt = batch->cnt;

  if( cnt == 0 ) {
    return (void *)batch;
  }

  /* Check if ALL messages have at least one full block.
     If any message is shorter than the rate, we must fall back to
     single-message processing to avoid corrupting short messages
     during parallel permutation. */
  int all_have_full_block = 1;
  for( ulong i = 0; i < cnt; i++ ) {
    if( batch->sz[i] < AT_KECCAK256_RATE ) {
      all_have_full_block = 0;
      break;
    }
  }

  if( cnt <= 3 || !all_have_full_block ) {
    for( ulong i = 0; i < cnt; i++ ) {
      at_keccak256_hash( batch->data[i], batch->sz[i], batch->hash[i] );
    }
    return (void *)batch;
  }

  ulong state[8][25] __attribute__((aligned(64)));
  at_memset( state, 0, sizeof(state) );

  ulong const * data_ptr[8];
  ulong         data_off[8];
  ulong         data_rem[8];

  for( ulong i = 0; i < 8; i++ ) {
    ulong idx = (i < cnt) ? i : 0;
    data_ptr[i] = (ulong const *)batch->data[idx];
    data_off[i] = 0;
    data_rem[i] = batch->sz[idx];
  }

  int any_full = 1;
  while( any_full ) {
    any_full = 0;

    for( ulong i = 0; i < 8; i++ ) {
      if( data_rem[i] >= AT_KECCAK256_RATE ) {
        uchar const * p = (uchar const *)data_ptr[i] + data_off[i];
        for( ulong j = 0; j < 17; j++ ) {
          ulong word;
          at_memcpy( &word, p + j*8, 8 );
          state[i][j] ^= word;
        }
        data_off[i] += AT_KECCAK256_RATE;
        data_rem[i] -= AT_KECCAK256_RATE;
        any_full = 1;
      }
    }

    if( any_full ) {
      keccak_f1600_x8( state );
    }
  }

  for( ulong i = 0; i < cnt; i++ ) {
    uchar const * p = (uchar const *)batch->data[i] + data_off[i];
    ulong rem = data_rem[i];

    uchar * state_bytes = (uchar *)state[i];
    for( ulong j = 0; j < rem; j++ ) {
      state_bytes[j] ^= p[j];
    }

    /* Keccak256 padding: 0x01 ... 0x80 */
    state_bytes[rem] ^= 0x01;
    state_bytes[AT_KECCAK256_RATE - 1] ^= 0x80;

    at_keccak256_core( state[i] );

    at_memcpy( batch->hash[i], state[i], AT_KECCAK256_OUT_SZ );
  }

  return (void *)batch;
}

#endif /* AT_KECCAK256_BATCH_IMPL==2 */
