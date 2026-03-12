/* Keccak256 AVX2 Batch Implementation

   This file implements parallel Keccak256 hashing using AVX2.
   Up to 4 independent messages are processed simultaneously.

   Keccak256 uses the same Keccak-f[1600] permutation as SHA3 but with
   different padding (0x01 instead of 0x06). */

#include "at_keccak256.h"
#include "at/infra/at_util.h"
#include "at_keccak256_private.h"

#if AT_KECCAK256_BATCH_IMPL==1

#include "at/infra/simd/at_avx.h"

/* Process 4 Keccak-f[1600] permutations in parallel using AVX2 */
static void
keccak_f1600_x4( ulong state[4][25] ) {

  /* Round constants */
  static ulong const rc[24] = {
    0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808AUL, 0x8000000080008000UL,
    0x000000000000808BUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008AUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000AUL,
    0x000000008000808BUL, 0x800000000000008BUL, 0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800AUL, 0x800000008000000AUL,
    0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
  };

  /* Load all 25 lanes from 4 states */
  wl_t s[25];
  for( int i = 0; i < 25; i++ ) {
    s[i] = wl( (long)state[0][i], (long)state[1][i], (long)state[2][i], (long)state[3][i] );
  }

  for( int round = 0; round < 24; round++ ) {

    /* Theta step */
    wl_t c[5];
    c[0] = wl_xor( wl_xor( wl_xor( s[0], s[5] ), wl_xor( s[10], s[15] ) ), s[20] );
    c[1] = wl_xor( wl_xor( wl_xor( s[1], s[6] ), wl_xor( s[11], s[16] ) ), s[21] );
    c[2] = wl_xor( wl_xor( wl_xor( s[2], s[7] ), wl_xor( s[12], s[17] ) ), s[22] );
    c[3] = wl_xor( wl_xor( wl_xor( s[3], s[8] ), wl_xor( s[13], s[18] ) ), s[23] );
    c[4] = wl_xor( wl_xor( wl_xor( s[4], s[9] ), wl_xor( s[14], s[19] ) ), s[24] );

    wl_t d[5];
    d[0] = wl_xor( c[4], wl_rol( c[1], 1 ) );
    d[1] = wl_xor( c[0], wl_rol( c[2], 1 ) );
    d[2] = wl_xor( c[1], wl_rol( c[3], 1 ) );
    d[3] = wl_xor( c[2], wl_rol( c[4], 1 ) );
    d[4] = wl_xor( c[3], wl_rol( c[0], 1 ) );

    for( int y = 0; y < 5; y++ ) {
      s[0 + 5*y] = wl_xor( s[0 + 5*y], d[0] );
      s[1 + 5*y] = wl_xor( s[1 + 5*y], d[1] );
      s[2 + 5*y] = wl_xor( s[2 + 5*y], d[2] );
      s[3 + 5*y] = wl_xor( s[3 + 5*y], d[3] );
      s[4 + 5*y] = wl_xor( s[4 + 5*y], d[4] );
    }

    /* Rho and Pi steps */
    wl_t b[25];
    b[ 0] = s[ 0];
    b[ 1] = wl_rol( s[ 6], 44 );
    b[ 2] = wl_rol( s[12], 43 );
    b[ 3] = wl_rol( s[18], 21 );
    b[ 4] = wl_rol( s[24], 14 );

    b[ 5] = wl_rol( s[ 3], 28 );
    b[ 6] = wl_rol( s[ 9], 20 );
    b[ 7] = wl_rol( s[10],  3 );
    b[ 8] = wl_rol( s[16], 45 );
    b[ 9] = wl_rol( s[22], 61 );

    b[10] = wl_rol( s[ 1],  1 );
    b[11] = wl_rol( s[ 7],  6 );
    b[12] = wl_rol( s[13], 25 );
    b[13] = wl_rol( s[19],  8 );
    b[14] = wl_rol( s[20], 18 );

    b[15] = wl_rol( s[ 4], 27 );
    b[16] = wl_rol( s[ 5], 36 );
    b[17] = wl_rol( s[11], 10 );
    b[18] = wl_rol( s[17], 15 );
    b[19] = wl_rol( s[23], 56 );

    b[20] = wl_rol( s[ 2], 62 );
    b[21] = wl_rol( s[ 8], 55 );
    b[22] = wl_rol( s[14], 39 );
    b[23] = wl_rol( s[15], 41 );
    b[24] = wl_rol( s[21],  2 );

    /* Chi step */
    for( int y = 0; y < 5; y++ ) {
      wl_t t0 = b[0 + 5*y];
      wl_t t1 = b[1 + 5*y];
      wl_t t2 = b[2 + 5*y];
      wl_t t3 = b[3 + 5*y];
      wl_t t4 = b[4 + 5*y];

      s[0 + 5*y] = wl_xor( t0, wl_andnot( t1, t2 ) );
      s[1 + 5*y] = wl_xor( t1, wl_andnot( t2, t3 ) );
      s[2 + 5*y] = wl_xor( t2, wl_andnot( t3, t4 ) );
      s[3 + 5*y] = wl_xor( t3, wl_andnot( t4, t0 ) );
      s[4 + 5*y] = wl_xor( t4, wl_andnot( t0, t1 ) );
    }

    /* Iota step */
    s[0] = wl_xor( s[0], wl_bcast( (long)rc[round] ) );
  }

  /* Store results */
  for( int i = 0; i < 25; i++ ) {
    state[0][i] = (ulong)wl_extract( s[i], 0 );
    state[1][i] = (ulong)wl_extract( s[i], 1 );
    state[2][i] = (ulong)wl_extract( s[i], 2 );
    state[3][i] = (ulong)wl_extract( s[i], 3 );
  }
}

void *
at_keccak256_batch_fini_avx2( at_keccak256_batch_t * batch ) {
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

  if( cnt <= 2 || !all_have_full_block ) {
    for( ulong i = 0; i < cnt; i++ ) {
      at_keccak256_hash( batch->data[i], batch->sz[i], batch->hash[i] );
    }
    return (void *)batch;
  }

  /* Initialize 4 states */
  ulong state[4][25] __attribute__((aligned(32)));
  at_memset( state, 0, sizeof(state) );

  ulong const * data_ptr[4];
  ulong         data_off[4];
  ulong         data_rem[4];

  for( ulong i = 0; i < 4; i++ ) {
    ulong idx = (i < cnt) ? i : 0;
    data_ptr[i] = (ulong const *)batch->data[idx];
    data_off[i] = 0;
    data_rem[i] = batch->sz[idx];
  }

  /* Process full blocks (136 bytes for Keccak256) */
  while( data_rem[0] >= AT_KECCAK256_RATE ||
         data_rem[1] >= AT_KECCAK256_RATE ||
         data_rem[2] >= AT_KECCAK256_RATE ||
         data_rem[3] >= AT_KECCAK256_RATE ) {

    for( ulong i = 0; i < 4; i++ ) {
      if( data_rem[i] >= AT_KECCAK256_RATE ) {
        uchar const * p = (uchar const *)data_ptr[i] + data_off[i];
        for( ulong j = 0; j < 17; j++ ) {
          ulong word;
          at_memcpy( &word, p + j*8, 8 );
          state[i][j] ^= word;
        }
        data_off[i] += AT_KECCAK256_RATE;
        data_rem[i] -= AT_KECCAK256_RATE;
      }
    }

    keccak_f1600_x4( state );
  }

  /* Finalize each state (Keccak256 uses 0x01 padding, not 0x06) */
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

#endif /* AT_KECCAK256_BATCH_IMPL==1 */
