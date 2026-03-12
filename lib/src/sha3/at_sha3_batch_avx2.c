/* SHA3 AVX2 Batch Implementation

   This file implements parallel SHA3-256 and SHA3-512 hashing using AVX2.
   Up to 4 independent messages are processed simultaneously.

   The approach uses "lane-interleaved" processing where we maintain
   4 independent Keccak states and process them in parallel. */

#include "at_sha3.h"
#include "at/infra/at_util.h"
#include "at_sha3_private.h"

#if AT_SHA3_512_BATCH_IMPL==1 || AT_SHA3_256_BATCH_IMPL==1

#include "at/infra/simd/at_avx.h"

/* For batch processing, we maintain N independent Keccak states
   and process them in parallel. Since each state is 25 x 64-bit,
   we use AVX2 to process 4 lanes at a time across 4 states. */

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

  /* Load all 25 lanes from 4 states into wl_t vectors
     Each wl_t holds lane[i] from all 4 states */
  wl_t s[25];
  for( int i = 0; i < 25; i++ ) {
    s[i] = wl( (long)state[0][i], (long)state[1][i], (long)state[2][i], (long)state[3][i] );
  }

  for( int round = 0; round < 24; round++ ) {

    /* Theta step: compute column parities */
    wl_t c[5];
    c[0] = wl_xor( wl_xor( wl_xor( s[0], s[5] ), wl_xor( s[10], s[15] ) ), s[20] );
    c[1] = wl_xor( wl_xor( wl_xor( s[1], s[6] ), wl_xor( s[11], s[16] ) ), s[21] );
    c[2] = wl_xor( wl_xor( wl_xor( s[2], s[7] ), wl_xor( s[12], s[17] ) ), s[22] );
    c[3] = wl_xor( wl_xor( wl_xor( s[3], s[8] ), wl_xor( s[13], s[18] ) ), s[23] );
    c[4] = wl_xor( wl_xor( wl_xor( s[4], s[9] ), wl_xor( s[14], s[19] ) ), s[24] );

    /* d[x] = c[(x+4) mod 5] ^ rot(c[(x+1) mod 5], 1) */
    wl_t d[5];
    d[0] = wl_xor( c[4], wl_rol( c[1], 1 ) );
    d[1] = wl_xor( c[0], wl_rol( c[2], 1 ) );
    d[2] = wl_xor( c[1], wl_rol( c[3], 1 ) );
    d[3] = wl_xor( c[2], wl_rol( c[4], 1 ) );
    d[4] = wl_xor( c[3], wl_rol( c[0], 1 ) );

    /* Apply theta to all lanes */
    for( int y = 0; y < 5; y++ ) {
      s[0 + 5*y] = wl_xor( s[0 + 5*y], d[0] );
      s[1 + 5*y] = wl_xor( s[1 + 5*y], d[1] );
      s[2 + 5*y] = wl_xor( s[2 + 5*y], d[2] );
      s[3 + 5*y] = wl_xor( s[3 + 5*y], d[3] );
      s[4 + 5*y] = wl_xor( s[4 + 5*y], d[4] );
    }

    /* Rho and Pi steps combined
       B[y, 2x+3y mod 5] = rot(A[x,y], rho[x,y]) */
    wl_t b[25];
    b[ 0] = s[ 0];                      /* (0,0) -> (0,0), rho=0 */
    b[ 1] = wl_rol( s[ 6], 44 );        /* (1,1) -> (0,1), rho=44 */
    b[ 2] = wl_rol( s[12], 43 );        /* (2,2) -> (0,2), rho=43 */
    b[ 3] = wl_rol( s[18], 21 );        /* (3,3) -> (0,3), rho=21 */
    b[ 4] = wl_rol( s[24], 14 );        /* (4,4) -> (0,4), rho=14 */

    b[ 5] = wl_rol( s[ 3], 28 );        /* (3,0) -> (1,0), rho=28 */
    b[ 6] = wl_rol( s[ 9], 20 );        /* (4,1) -> (1,1), rho=20 */
    b[ 7] = wl_rol( s[10],  3 );        /* (0,2) -> (1,2), rho=3 */
    b[ 8] = wl_rol( s[16], 45 );        /* (1,3) -> (1,3), rho=45 */
    b[ 9] = wl_rol( s[22], 61 );        /* (2,4) -> (1,4), rho=61 */

    b[10] = wl_rol( s[ 1],  1 );        /* (1,0) -> (2,0), rho=1 */
    b[11] = wl_rol( s[ 7],  6 );        /* (2,1) -> (2,1), rho=6 */
    b[12] = wl_rol( s[13], 25 );        /* (3,2) -> (2,2), rho=25 */
    b[13] = wl_rol( s[19],  8 );        /* (4,3) -> (2,3), rho=8 */
    b[14] = wl_rol( s[20], 18 );        /* (0,4) -> (2,4), rho=18 */

    b[15] = wl_rol( s[ 4], 27 );        /* (4,0) -> (3,0), rho=27 */
    b[16] = wl_rol( s[ 5], 36 );        /* (0,1) -> (3,1), rho=36 */
    b[17] = wl_rol( s[11], 10 );        /* (1,2) -> (3,2), rho=10 */
    b[18] = wl_rol( s[17], 15 );        /* (2,3) -> (3,3), rho=15 */
    b[19] = wl_rol( s[23], 56 );        /* (3,4) -> (3,4), rho=56 */

    b[20] = wl_rol( s[ 2], 62 );        /* (2,0) -> (4,0), rho=62 */
    b[21] = wl_rol( s[ 8], 55 );        /* (3,1) -> (4,1), rho=55 */
    b[22] = wl_rol( s[14], 39 );        /* (4,2) -> (4,2), rho=39 */
    b[23] = wl_rol( s[15], 41 );        /* (0,3) -> (4,3), rho=41 */
    b[24] = wl_rol( s[21],  2 );        /* (1,4) -> (4,4), rho=2 */

    /* Chi step: s[x,y] = b[x,y] ^ ((~b[x+1,y]) & b[x+2,y]) */
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

    /* Iota step: XOR round constant into lane 0 */
    s[0] = wl_xor( s[0], wl_bcast( (long)rc[round] ) );
  }

  /* Store results back to states */
  for( int i = 0; i < 25; i++ ) {
    state[0][i] = (ulong)wl_extract( s[i], 0 );
    state[1][i] = (ulong)wl_extract( s[i], 1 );
    state[2][i] = (ulong)wl_extract( s[i], 2 );
    state[3][i] = (ulong)wl_extract( s[i], 3 );
  }
}

#endif /* AT_SHA3_512_BATCH_IMPL==1 || AT_SHA3_256_BATCH_IMPL==1 */

/**********************************************************************/
/* SHA3-512 Batch AVX2                                                 */
/**********************************************************************/

#if AT_SHA3_512_BATCH_IMPL==1

void *
at_sha3_512_batch_fini_avx2( at_sha3_512_batch_t * batch ) {
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
    if( batch->sz[i] < AT_SHA3_512_RATE ) {
      all_have_full_block = 0;
      break;
    }
  }

  /* If only 1-2 messages, or any message is too short, use sequential */
  if( cnt <= 2 || !all_have_full_block ) {
    for( ulong i = 0; i < cnt; i++ ) {
      at_sha3_512_hash( batch->data[i], batch->sz[i], batch->hash[i] );
    }
    return (void *)batch;
  }

  /* Initialize 4 states */
  ulong state[4][25] __attribute__((aligned(32)));
  at_memset( state, 0, sizeof(state) );

  /* Process each message up to cnt (pad with duplicates if needed) */
  ulong const * data_ptr[4];
  ulong         data_off[4];
  ulong         data_rem[4];

  for( ulong i = 0; i < 4; i++ ) {
    ulong idx = (i < cnt) ? i : 0;  /* Duplicate first message for unused slots */
    data_ptr[i] = (ulong const *)batch->data[idx];
    data_off[i] = 0;
    data_rem[i] = batch->sz[idx];
  }

  /* Process full blocks (72 bytes = 9 ulongs for SHA3-512) */
  while( data_rem[0] >= AT_SHA3_512_RATE ||
         data_rem[1] >= AT_SHA3_512_RATE ||
         data_rem[2] >= AT_SHA3_512_RATE ||
         data_rem[3] >= AT_SHA3_512_RATE ) {

    /* Absorb rate bytes into each state that has enough data */
    for( ulong i = 0; i < 4; i++ ) {
      if( data_rem[i] >= AT_SHA3_512_RATE ) {
        uchar const * p = (uchar const *)data_ptr[i] + data_off[i];
        for( ulong j = 0; j < 9; j++ ) {
          ulong word;
          at_memcpy( &word, p + j*8, 8 );
          state[i][j] ^= word;
        }
        data_off[i] += AT_SHA3_512_RATE;
        data_rem[i] -= AT_SHA3_512_RATE;
      }
    }

    /* Apply permutation to all states in parallel */
    keccak_f1600_x4( state );
  }

  /* Finalize each state individually (different padding lengths) */
  for( ulong i = 0; i < cnt; i++ ) {
    uchar const * p = (uchar const *)batch->data[i] + data_off[i];
    ulong rem = data_rem[i];

    /* XOR remaining bytes into state */
    uchar * state_bytes = (uchar *)state[i];
    for( ulong j = 0; j < rem; j++ ) {
      state_bytes[j] ^= p[j];
    }

    /* SHA3 padding: 0x06 ... 0x80 */
    state_bytes[rem] ^= 0x06;
    state_bytes[AT_SHA3_512_RATE - 1] ^= 0x80;

    /* Final permutation */
    at_sha3_keccak_core( state[i] );

    /* Copy output */
    at_memcpy( batch->hash[i], state[i], AT_SHA3_512_OUT_SZ );
  }

  return (void *)batch;
}

#endif /* AT_SHA3_512_BATCH_IMPL==1 */

/**********************************************************************/
/* SHA3-256 Batch AVX2                                                 */
/**********************************************************************/

#if AT_SHA3_256_BATCH_IMPL==1

void *
at_sha3_256_batch_fini_avx2( at_sha3_256_batch_t * batch ) {
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
    if( batch->sz[i] < AT_SHA3_256_RATE ) {
      all_have_full_block = 0;
      break;
    }
  }

  /* If only 1-2 messages, or any message is too short, use sequential */
  if( cnt <= 2 || !all_have_full_block ) {
    for( ulong i = 0; i < cnt; i++ ) {
      at_sha3_256_hash( batch->data[i], batch->sz[i], batch->hash[i] );
    }
    return (void *)batch;
  }

  /* Initialize 4 states */
  ulong state[4][25] __attribute__((aligned(32)));
  at_memset( state, 0, sizeof(state) );

  /* Process each message up to cnt (pad with duplicates if needed) */
  ulong const * data_ptr[4];
  ulong         data_off[4];
  ulong         data_rem[4];

  for( ulong i = 0; i < 4; i++ ) {
    ulong idx = (i < cnt) ? i : 0;
    data_ptr[i] = (ulong const *)batch->data[idx];
    data_off[i] = 0;
    data_rem[i] = batch->sz[idx];
  }

  /* Process full blocks (136 bytes = 17 ulongs for SHA3-256) */
  while( data_rem[0] >= AT_SHA3_256_RATE ||
         data_rem[1] >= AT_SHA3_256_RATE ||
         data_rem[2] >= AT_SHA3_256_RATE ||
         data_rem[3] >= AT_SHA3_256_RATE ) {

    for( ulong i = 0; i < 4; i++ ) {
      if( data_rem[i] >= AT_SHA3_256_RATE ) {
        uchar const * p = (uchar const *)data_ptr[i] + data_off[i];
        for( ulong j = 0; j < 17; j++ ) {
          ulong word;
          at_memcpy( &word, p + j*8, 8 );
          state[i][j] ^= word;
        }
        data_off[i] += AT_SHA3_256_RATE;
        data_rem[i] -= AT_SHA3_256_RATE;
      }
    }

    keccak_f1600_x4( state );
  }

  /* Finalize each state */
  for( ulong i = 0; i < cnt; i++ ) {
    uchar const * p = (uchar const *)batch->data[i] + data_off[i];
    ulong rem = data_rem[i];

    uchar * state_bytes = (uchar *)state[i];
    for( ulong j = 0; j < rem; j++ ) {
      state_bytes[j] ^= p[j];
    }

    state_bytes[rem] ^= 0x06;
    state_bytes[AT_SHA3_256_RATE - 1] ^= 0x80;

    at_sha3_keccak_core( state[i] );

    at_memcpy( batch->hash[i], state[i], AT_SHA3_256_OUT_SZ );
  }

  return (void *)batch;
}

#endif /* AT_SHA3_256_BATCH_IMPL==1 */
