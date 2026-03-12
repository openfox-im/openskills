#include "./at_poseidon.h"
#include "at_poseidon_params.c"

/* Poseidon internals */

static inline void
at_poseidon_apply_ark( at_bn254_scalar_t         state[],
                       ulong const               width,
                       at_poseidon_par_t const * params,
                       ulong                     round ) {
  for( ulong i=0; i<width; i++ ) {
    at_bn254_scalar_add( &state[i], &state[i], &params->ark[ round * width + i ] );
  }
}

static inline void
at_poseidon_apply_sbox_full( at_bn254_scalar_t state[],
                             ulong const       width ) {
  /* Compute s[i]^5 */
  for( ulong i=0; i<width; i++ ) {
    at_bn254_scalar_t t[1];
    at_bn254_scalar_sqr( t, &state[i] );            /* t = s^2 */
    at_bn254_scalar_sqr( t, t );                    /* t = s^4 */
    at_bn254_scalar_mul( &state[i], &state[i], t ); /* s = s^5 */
  }
}

static inline void
at_poseidon_apply_sbox_partial( at_bn254_scalar_t state[] ) {
  /* Compute s[0]^5 */
  at_poseidon_apply_sbox_full( state, 1 );
}

static inline void
at_poseidon_apply_mds( at_bn254_scalar_t   state[],
                       ulong const       width,
                       at_poseidon_par_t const * params ) {
  at_bn254_scalar_t x[AT_POSEIDON_MAX_WIDTH+1] = { 0 };
  /* Vector-matrix multiplication (state vector times mds matrix) */
  for( ulong i=0; i<width; i++ ) {
    for( ulong j=0; j<width; j++ ) {
      at_bn254_scalar_t t[1];
      at_bn254_scalar_mul( t, &state[j], &params->mds[ i * width + j ] );
      at_bn254_scalar_add( &x[i], &x[i], t );
    }
  }
  for( ulong i=0; i<width; i++ ) {
    state[i] = x[i];
  }
}

static inline void
at_poseidon_get_params( at_poseidon_par_t * params,
                        ulong const         width ) {
#define AT_POSEIDON_GET_PARAMS(w) case (w):                \
  params->ark = (at_bn254_scalar_t *)at_poseidon_ark_## w; \
  params->mds = (at_bn254_scalar_t *)at_poseidon_mds_## w; \
  break

  switch( width ) {
  AT_POSEIDON_GET_PARAMS(2);
  AT_POSEIDON_GET_PARAMS(3);
  AT_POSEIDON_GET_PARAMS(4);
  AT_POSEIDON_GET_PARAMS(5);
  AT_POSEIDON_GET_PARAMS(6);
  AT_POSEIDON_GET_PARAMS(7);
  AT_POSEIDON_GET_PARAMS(8);
  AT_POSEIDON_GET_PARAMS(9);
  AT_POSEIDON_GET_PARAMS(10);
  AT_POSEIDON_GET_PARAMS(11);
  AT_POSEIDON_GET_PARAMS(12);
  AT_POSEIDON_GET_PARAMS(13);
  }
#undef AT_POSEIDON_GET_PARAMS
}

/* Poseidon interface */

at_poseidon_t *
at_poseidon_init( at_poseidon_t * pos,
                  int const       big_endian ) {
  if( AT_UNLIKELY( pos==NULL ) ) {
    return NULL;
  }
  pos->big_endian = big_endian;
  pos->cnt = 0UL;
  at_memset( pos->state, 0, sizeof(pos->state) );
  return pos;
}

at_poseidon_t *
at_poseidon_append( at_poseidon_t * pos,
                    uchar const *   data,
                    ulong           sz,
                    int             enforce_padding ) {
  if( AT_UNLIKELY( pos==NULL ) ) {
    return NULL;
  }
  if( AT_UNLIKELY( pos->cnt >= AT_POSEIDON_MAX_WIDTH ) ) {
    return NULL;
  }
  if( AT_UNLIKELY( enforce_padding && sz!=32UL ) ) {
    return NULL;
  }
  /* Empty input and non-field are errors. Short element is extended with 0s. */
  if( AT_UNLIKELY( sz==0 || sz>32UL ) ) {
    return NULL;
  }

  /* Handle endianness */
  at_bn254_scalar_t cur[1] = { 0 };
  at_memcpy( cur->buf + (32-sz)*(pos->big_endian?1:0), data, sz );
  if( pos->big_endian ) {
    at_uint256_bswap( cur, cur );
  }

  if( AT_UNLIKELY( !at_bn254_scalar_validate( cur ) ) ) {
    return NULL;
  }
  pos->cnt++;
  at_bn254_scalar_to_mont( &pos->state[ pos->cnt ], cur );

  return pos;
}

uchar *
at_poseidon_fini( at_poseidon_t * pos,
                  uchar           hash[ AT_POSEIDON_HASH_SZ ] ) {
  if( AT_UNLIKELY( pos==NULL ) ) {
    return NULL;
  }
  if( AT_UNLIKELY( !pos->cnt ) ) {
    return NULL;
  }
  const ulong width = pos->cnt+1;
  at_poseidon_par_t params[1] = { 0 };
  at_poseidon_get_params( params, width );
  if( AT_UNLIKELY( !params->ark || !params->mds ) ) {
    return NULL;
  }

  const ulong PARTIAL_ROUNDS[] = { 56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68 };
  const ulong partial_rounds = PARTIAL_ROUNDS[ pos->cnt-1 ];
  const ulong full_rounds = 8;
  const ulong half_rounds = full_rounds / 2;
  const ulong all_rounds = full_rounds + partial_rounds;

  ulong round=0;
  for (; round<half_rounds; round++ ) {
    at_poseidon_apply_ark         ( pos->state, width, params, round );
    at_poseidon_apply_sbox_full   ( pos->state, width );
    at_poseidon_apply_mds         ( pos->state, width, params );
  }

  for (; round<half_rounds+partial_rounds; round++ ) {
    at_poseidon_apply_ark         ( pos->state, width, params, round );
    at_poseidon_apply_sbox_partial( pos->state );
    at_poseidon_apply_mds         ( pos->state, width, params );
  }

  for (; round<all_rounds; round++ ) {
    at_poseidon_apply_ark         ( pos->state, width, params, round );
    at_poseidon_apply_sbox_full   ( pos->state, width );
    at_poseidon_apply_mds         ( pos->state, width, params );
  }

  /* Directly convert scalar into return hash buffer - hash MUST be AT_UINT256_ALIGNED */
  at_bn254_scalar_t scalar_hash[1];
  at_bn254_scalar_from_mont( scalar_hash, &pos->state[0] );
  if( pos->big_endian ) {
    at_uint256_bswap( scalar_hash, scalar_hash );
  }
  at_memcpy( hash, scalar_hash, 32 );
  return hash;
}