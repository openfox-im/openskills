#include "./at_bn254_internal.h"

#include "./at_bn254_field.c"
#include "./at_bn254_field_ext.c"
#include "./at_bn254_g1.c"
#include "./at_bn254_g2.c"
#include "./at_bn254_pairing.c"

/* Compress/Decompress */

uchar *
at_bn254_g1_compress( uchar       out[32],
                      uchar const in [64],
                      int         big_endian ) {
  at_bn254_g1_t p[1] = { 0 };
  if( AT_UNLIKELY( !at_bn254_g1_frombytes_internal( p, in, big_endian ) ) ) {
    return NULL;
  }
  int is_inf   = at_bn254_g1_is_zero( p );
  int flag_inf = in[ big_endian ? 32 : 63 ] & FLAG_INF;

  /* Serialize compressed point:
     https://github.com/arkworks-rs/algebra/blob/v0.4.2/ec/src/models/short_weierstrass/mod.rs#L122

     1. If the infinity flags is set, return point at infinity
     2. Else, copy x and set neg_y flag */

  if( AT_UNLIKELY( is_inf ) ) {
    at_memset( out, 0, 32 );
    /* The infinity flag in the result is set iff the infinity flag is set in the Y coordinate */
    out[0] = (uchar)( out[0] | flag_inf );
    return out;
  }

  int is_neg = at_bn254_fp_is_neg_nm( &p->Y );
  at_bn254_fp_tobytes_nm( out, &p->X, big_endian );
  if( is_neg ) {
    out[ big_endian ? 0 : 31 ] = (uchar)( out[ big_endian ? 0 : 31 ] | FLAG_NEG );
  }
  return out;
}

uchar *
at_bn254_g1_decompress( uchar       out[64],
                        uchar const in [32],
                        int         big_endian ) {
  /* Special case: all zeros in => all zeros out, no flags */
  const uchar zero[32] = { 0 };
  if( at_memeq( in, zero, 32 ) ) {
    return at_memset( out, 0, 64UL );
  }

  at_bn254_fp_t x_nm[1], x[1], x2[1], x3_plus_b[1], y[1];
  int is_inf, is_neg;
  if( AT_UNLIKELY( !at_bn254_fp_frombytes_nm( x_nm, in, big_endian, &is_inf, &is_neg ) ) ) {
    return NULL;
  }

  /* Point at infinity.
     If the point at infinity flag is set (bit 6), return the point at
     infinity with no check on coords.
     https://github.com/arkworks-rs/algebra/blob/v0.4.2/ec/src/models/short_weierstrass/mod.rs#L156-L160
  */
  if( is_inf ) {
    at_memset( out, 0, 64UL );
    /* no flags */
    return out;
  }

  at_bn254_fp_to_mont( x, x_nm );
  at_bn254_fp_sqr( x2, x );
  at_bn254_fp_mul( x3_plus_b, x2, x );
  at_bn254_fp_add( x3_plus_b, x3_plus_b, at_bn254_const_b_mont );
  if( AT_UNLIKELY( !at_bn254_fp_sqrt( y, x3_plus_b ) ) ) {
    return NULL;
  }

  at_bn254_fp_from_mont( y, y );
  if( is_neg != at_bn254_fp_is_neg_nm( y ) ) {
    at_bn254_fp_neg_nm( y, y );
  }

  at_bn254_fp_tobytes_nm(  out,     x_nm, big_endian );
  at_bn254_fp_tobytes_nm( &out[32], y,    big_endian );
  /* no flags */
  return out;
}

uchar *
at_bn254_g2_compress( uchar       out[64],
                      uchar const in[128],
                      int         big_endian ) {
  at_bn254_g2_t p[1] = { 0 };
  if( AT_UNLIKELY( !at_bn254_g2_frombytes_internal( p, in, big_endian ) ) ) {
    return NULL;
  }
  int is_inf   = at_bn254_g2_is_zero( p );
  int flag_inf = in[64] & FLAG_INF;

  /* Serialize compressed point */

  if( AT_UNLIKELY( is_inf ) ) {
    at_memset( out, 0, 64 );
    /* The infinity flag in the result is set iff the infinity flag is set in the Y coordinate */
    out[0] = (uchar)( out[0] | flag_inf );
    return out;
  }

  /* Serialize x coordinate. The flags are on the 2nd element.
     https://github.com/arkworks-rs/algebra/blob/v0.4.2/ff/src/fields/models/quadratic_extension.rs#L700-L702 */
  int is_neg = at_bn254_fp2_is_neg_nm( &p->Y );
  at_bn254_fp2_tobytes_nm( out, &p->X, big_endian );
  if( is_neg ) {
    out[ big_endian ? 0 : 63 ] = (uchar)( out[ big_endian ? 0 : 63 ] | FLAG_NEG );
  }
  return out;
}

uchar *
at_bn254_g2_decompress( uchar       out[128],
                        uchar const in  [64],
                        int         big_endian ) {
  /* Special case: all zeros in => all zeros out, no flags */
  const uchar zero[64] = { 0 };
  if( at_memeq( in, zero, 64 ) ) {
    return at_memset( out, 0, 128UL );
  }

  at_bn254_fp2_t x_nm[1], x[1], x2[1], x3_plus_b[1], y[1];
  int is_inf, is_neg;
  if( AT_UNLIKELY( !at_bn254_fp2_frombytes_nm( x_nm, in, big_endian, &is_inf, &is_neg ) ) ) {
    return NULL;
  }

  /* Point at infinity.
     If the point at infinity flag is set (bit 6), return the point at
     infinity with no check on coords.
     https://github.com/arkworks-rs/algebra/blob/v0.4.2/ec/src/models/short_weierstrass/mod.rs#L156-L160 */
  if( is_inf ) {
    at_memset( out, 0, 128UL );
    /* no flags */
    return out;
  }

  at_bn254_fp2_to_mont( x, x_nm );
  at_bn254_fp2_sqr( x2, x );
  at_bn254_fp2_mul( x3_plus_b, x2, x );
  at_bn254_fp2_add( x3_plus_b, x3_plus_b, at_bn254_const_twist_b_mont );
  if( AT_UNLIKELY( !at_bn254_fp2_sqrt( y, x3_plus_b ) ) ) {
    return NULL;
  }

  at_bn254_fp2_from_mont( y, y );
  if( is_neg != at_bn254_fp2_is_neg_nm( y ) ) {
    at_bn254_fp2_neg_nm( y, y );
  }

  at_bn254_fp2_tobytes_nm(  out,     x_nm, big_endian );
  at_bn254_fp2_tobytes_nm( &out[64], y,    big_endian );
  /* no flags */
  return out;
}

/* Ops */

int
at_bn254_g1_add_syscall( uchar       out[64],
                         uchar const in[],
                         ulong       in_sz,
                         int         big_endian ) {
  /* Expected 128-byte input (2 points). Pad input with 0s (only big endian). */
  if( AT_UNLIKELY( in_sz > 128UL ) ) {
    return -1;
  }
  if( AT_UNLIKELY( !big_endian && in_sz != 128UL ) ) {
    return -1;
  }
  uchar AT_ALIGNED buf[128] = { 0 };
  at_memcpy( buf, in, in_sz );

  /* Validate inputs */
  at_bn254_g1_t r[1], a[1], b[1];
  if( AT_UNLIKELY( !at_bn254_g1_frombytes_check_subgroup( a, &buf[ 0], big_endian ) ) ) {
    return -1;
  }
  if( AT_UNLIKELY( !at_bn254_g1_frombytes_check_subgroup( b, &buf[64], big_endian ) ) ) {
    return -1;
  }

  /* Compute point add and serialize result */
  at_bn254_g1_affine_add( r, a, b );
  at_bn254_g1_tobytes( out, r, big_endian );
  return 0;
}

int
at_bn254_g2_add_syscall( uchar       out[128],
                         uchar const in[],
                         ulong       in_sz,
                         int         big_endian ) {
  /* Expected 256-byte input (2 points). */
  if( AT_UNLIKELY( in_sz != 256UL ) ) {
    return -1;
  }
  uchar AT_ALIGNED buf[256] = { 0 };
  at_memcpy( buf, in, in_sz );

  /* Validate inputs (curve eq only, no subgroup) */
  at_bn254_g2_t r[1], a[1], b[1];
  if( AT_UNLIKELY( !at_bn254_g2_frombytes_check_eq_only( a, &buf[ 0], big_endian ) ) ) {
    return -1;
  }
  if( AT_UNLIKELY( !at_bn254_g2_frombytes_check_eq_only( b, &buf[128], big_endian ) ) ) {
    return -1;
  }

  /* Compute point add and serialize result */
  at_bn254_g2_add_mixed( r, a, b );
  at_bn254_g2_tobytes( out, r, big_endian );
  return 0;
}

int
at_bn254_g1_scalar_mul_syscall( uchar       out[64],
                                uchar const in[],
                                ulong       in_sz,
                                int         big_endian ) {
  /* Expected 96-byte input (1 point + 1 scalar). Pad input with 0s (only big endian). */
  if( AT_UNLIKELY( in_sz > 96UL ) ) {
    return -1;
  }
  if( AT_UNLIKELY( !big_endian && in_sz != 96UL ) ) {
    return -1;
  }
  uchar AT_ALIGNED buf[96] = { 0 };
  at_memcpy( buf, in, at_ulong_min( in_sz, 96UL ) );

  /* Validate inputs */
  at_bn254_g1_t r[1], a[1];
  at_bn254_scalar_t s[1];
  if( AT_UNLIKELY( !at_bn254_g1_frombytes_check_subgroup( a, &buf[ 0], big_endian ) ) ) {
    return -1;
  }

  /* Scalar is big endian and NOT validated.
     This matches the EVM alt_bn128 precompile behavior. */
  if( AT_BIG_ENDIAN_LIKELY( big_endian ) ) {
    at_uint256_bswap( s, at_type_pun_const( &buf[64] ) ); /* &buf[64] is always AT_ALIGNED */
  } else {
    at_memcpy( s, &buf[64], 32 );
  }
  // no: if( AT_UNLIKELY( !at_bn254_scalar_validate( s ) ) ) return -1;

  /* Compute scalar mul and serialize result */
  at_bn254_g1_scalar_mul( r, a, s );
  at_bn254_g1_tobytes( out, r, big_endian );
  return 0;
}

int
at_bn254_g2_scalar_mul_syscall( uchar       out[128],
                                uchar const in[],
                                ulong       in_sz,
                                int         big_endian ) {
  /* Expected 160-byte input (1 point + 1 scalar). */
  if( AT_UNLIKELY( in_sz != 160UL ) ) {
    return -1;
  }
  uchar AT_ALIGNED buf[160] = { 0 };
  at_memcpy( buf, in, 160UL );

  /* Validate point (curve equation and subgroup membership) */
  at_bn254_g2_t r[1], a[1];
  at_bn254_scalar_t s[1];
  if( AT_UNLIKELY( !at_bn254_g2_frombytes_check_subgroup( a, &buf[ 0], big_endian ) ) ) {
    return -1;
  }

  /* Scalar is little endian and NOT validated */
  if( AT_BIG_ENDIAN_LIKELY( big_endian ) ) {
    at_uint256_bswap( s, at_type_pun_const( &buf[128] ) ); /* &buf[128] is always AT_ALIGNED */
  } else {
    at_memcpy( s, &buf[128], 32 );
  }
  // no: if( AT_UNLIKELY( !at_bn254_scalar_validate( s ) ) ) return -1;

  /* Compute scalar mul and serialize result */
  at_bn254_g2_scalar_mul( r, a, s );
  at_bn254_g2_tobytes( out, r, big_endian );
  return 0;
}

int
at_bn254_pairing_is_one_syscall( uchar       out[32],
                                 uchar const in[],
                                 ulong       in_sz,
                                 int         big_endian,
                                 int         check_len ) {
  /* When check_len is true, we properly validate that input size is a multiple of 192. */
  if( check_len ) {
    if( AT_UNLIKELY( (in_sz % 192UL) != 0 ) ) {
      return -1; /* Invalid input length */
    }
  }
  ulong elements_len = in_sz / 192UL;
  at_bn254_g1_t p[AT_BN254_PAIRING_BATCH_MAX];
  at_bn254_g2_t q[AT_BN254_PAIRING_BATCH_MAX];

  /* Important: set r=1 so that the result of 0 pairings is 1. */
  at_bn254_fp12_t r[1];
  at_bn254_fp12_set_one( r );

  ulong sz=0;
  for( ulong i=0; i<elements_len; i++ ) {
    /* G1: deserialize and check subgroup membership */
    if( AT_UNLIKELY( !at_bn254_g1_frombytes_check_subgroup( &p[sz], &in[i*192   ], big_endian ) ) ) {
      return -1;
    }
    /* G2: deserialize and check subgroup membership */
    if( AT_UNLIKELY( !at_bn254_g2_frombytes_check_subgroup( &q[sz], &in[i*192+64], big_endian ) ) ) {
      return -1;
    }
    /* Skip any pair where either P or Q is the point at infinity */
    if( AT_UNLIKELY( at_bn254_g1_is_zero(&p[sz]) || at_bn254_g2_is_zero(&q[sz]) ) ) {
      continue;
    }
    ++sz;
    /* Compute the Miller loop and aggregate into r */
    if( sz==AT_BN254_PAIRING_BATCH_MAX || i==elements_len-1 ) {
      at_bn254_fp12_t tmp[1];
      at_bn254_miller_loop( tmp, p, q, sz );
      at_bn254_fp12_mul( r, r, tmp );
      sz = 0;
    }
  }
  if( sz>0 ) {
    at_bn254_fp12_t tmp[1];
    at_bn254_miller_loop( tmp, p, q, sz );
    at_bn254_fp12_mul( r, r, tmp );
    sz = 0;
  }

  /* Compute the final exponentiation */
  at_bn254_final_exp( r, r );

  /* Output is 0 or 1, serialized as big endian uint256. */
  at_memset( out, 0, 32 );
  if( AT_LIKELY( at_bn254_fp12_is_one( r ) ) ) {
    out[ big_endian ? 31 : 0 ] = 1;
  }
  return 0;
}