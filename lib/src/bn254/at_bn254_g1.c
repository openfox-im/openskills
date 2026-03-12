#include "at_bn254.h"

/* G1 */

static inline int
at_bn254_g1_is_zero( at_bn254_g1_t const * p ) {
  return at_bn254_fp_is_zero( &p->Z );
}

static inline at_bn254_g1_t *
at_bn254_g1_set( at_bn254_g1_t *       r,
                 at_bn254_g1_t const * p ) {
  at_bn254_fp_set( &r->X, &p->X );
  at_bn254_fp_set( &r->Y, &p->Y );
  at_bn254_fp_set( &r->Z, &p->Z );
  return r;
}

static inline at_bn254_g1_t *
at_bn254_g1_set_zero( at_bn254_g1_t * r ) {
  // at_bn254_fp_set_zero( &r->X );
  // at_bn254_fp_set_zero( &r->Y );
  at_bn254_fp_set_zero( &r->Z );
  return r;
}

static inline at_bn254_g1_t *
at_bn254_g1_to_affine( at_bn254_g1_t *       r,
                       at_bn254_g1_t const * p ) {
  if( AT_UNLIKELY( at_bn254_fp_is_zero( &p->Z ) || at_bn254_fp_is_one( &p->Z ) ) ) {
    return at_bn254_g1_set( r, p );
  }

  at_bn254_fp_t iz[1], iz2[1];
  at_bn254_fp_inv( iz, &p->Z );
  at_bn254_fp_sqr( iz2, iz );

  /* X / Z^2, Y / Z^3 */
  at_bn254_fp_mul( &r->X, &p->X, iz2 );
  at_bn254_fp_mul( &r->Y, &p->Y, iz2 );
  at_bn254_fp_mul( &r->Y, &r->Y, iz );
  at_bn254_fp_set_one( &r->Z );
  return r;
}

uchar *
at_bn254_g1_tobytes( uchar                 out[64],
                     at_bn254_g1_t const * p,
                     int                   big_endian ) {
  if( AT_UNLIKELY( at_bn254_g1_is_zero( p ) ) ) {
    at_memset( out, 0, 64UL );
    /* no flags */
    return out;
  }

  at_bn254_g1_t r[1];
  at_bn254_g1_to_affine( r, p );

  at_bn254_fp_from_mont( &r->X, &r->X );
  at_bn254_fp_from_mont( &r->Y, &r->Y );

  at_bn254_fp_tobytes_nm( &out[ 0], &r->X, big_endian );
  at_bn254_fp_tobytes_nm( &out[32], &r->Y, big_endian );
  /* no flags */
  return out;
}

/* at_bn254_g1_affine_add computes r = p + q.
   Both p, q are affine, i.e. Z==1. */
at_bn254_g1_t *
at_bn254_g1_affine_add( at_bn254_g1_t *       r,
                        at_bn254_g1_t const * p,
                        at_bn254_g1_t const * q ) {
  /* p==0, return q */
  if( AT_UNLIKELY( at_bn254_g1_is_zero( p ) ) ) {
    return at_bn254_g1_set( r, q );
  }
  /* q==0, return p */
  if( AT_UNLIKELY( at_bn254_g1_is_zero( q ) ) ) {
    return at_bn254_g1_set( r, p );
  }

  at_bn254_fp_t lambda[1], x[1], y[1];

  /* same X, either the points are equal or opposite */
  if( at_bn254_fp_eq( &p->X, &q->X ) ) {
    if( at_bn254_fp_eq( &p->Y, &q->Y ) ) {
      /* p==q => point double: lambda = 3 * x1^2 / (2 * y1) */
      at_bn254_fp_sqr( x, &p->X ); /* x =   x1^2 */
      at_bn254_fp_add( y, x, x );  /* y = 2 x1^2 */
      at_bn254_fp_add( x, x, y );  /* x = 3 x1^2 */
      at_bn254_fp_add( y, &p->Y, &p->Y );
      at_bn254_fp_inv( lambda, y );
      at_bn254_fp_mul( lambda, lambda, x );
    } else {
      /* p==-q => r=0 */
      /* COV: this may never happen with real data */
      return at_bn254_g1_set_zero( r );
    }
  } else {
    /* point add: lambda = (y1 - y2) / (x1 - x2) */
    at_bn254_fp_sub( x, &p->X, &q->X );
    at_bn254_fp_sub( y, &p->Y, &q->Y );
    at_bn254_fp_inv( lambda, x );
    at_bn254_fp_mul( lambda, lambda, y );
  }

  /* x3 = lambda^2 - x1 - x2 */
  at_bn254_fp_sqr( x, lambda );
  at_bn254_fp_sub( x, x, &p->X );
  at_bn254_fp_sub( x, x, &q->X );

  /* y3 = lambda * (x1 - x3) - y1 */
  at_bn254_fp_sub( y, &p->X, x );
  at_bn254_fp_mul( y, y, lambda );
  at_bn254_fp_sub( y, y, &p->Y );

  at_bn254_fp_set( &r->X, x );
  at_bn254_fp_set( &r->Y, y );
  at_bn254_fp_set_one( &r->Z );
  return r;
}

/* at_bn254_g1_dbl computes r = 2p.
   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l */
at_bn254_g1_t *
at_bn254_g1_dbl( at_bn254_g1_t *       r,
                 at_bn254_g1_t const * p ) {
  /* p==0, return 0 */
  if( AT_UNLIKELY( at_bn254_g1_is_zero( p ) ) ) {
    return at_bn254_g1_set_zero( r );
  }

  at_bn254_fp_t a[1], b[1], c[1];
  at_bn254_fp_t d[1], e[1], f[1];

  /* A = X1^2 */
  at_bn254_fp_sqr( a, &p->X );
  /* B = Y1^2 */
  at_bn254_fp_sqr( b, &p->Y );
  /* C = B^2 */
  at_bn254_fp_sqr( c, b );
  /* D = 2*((X1+B)^2-A-C)
     (X1+B)^2 = X1^2 + 2*X1*B + B^2
     D = 2*(X1^2 + 2*X1*B + B^2 - A    - C)
     D = 2*(X1^2 + 2*X1*B + B^2 - X1^2 - B^2)
            ^               ^     ^      ^
            |---------------|-----|      |
                            |------------|
     These terms cancel each other out, and we're left with:
     D = 2*(2*X1*B) */
  at_bn254_fp_mul( d, &p->X, b );
  at_bn254_fp_add( d, d, d );
  at_bn254_fp_add( d, d, d );
  /* E = 3*A */
  at_bn254_fp_add( e, a, a );
  at_bn254_fp_add( e, a, e );
  /* F = E^2 */
  at_bn254_fp_sqr( f, e );
  /* X3 = F-2*D */
  at_bn254_fp_add( &r->X, d, d );
  at_bn254_fp_sub( &r->X, f, &r->X );
  /* Z3 = (Y1+Z1)^2-YY-ZZ
     note: compute Z3 before Y3 because it depends on p->Y,
     that might be overwritten if r==p. */
  /* Z3 = 2*Y1*Z1 */
  at_bn254_fp_mul( &r->Z, &p->Y, &p->Z );
  at_bn254_fp_add( &r->Z, &r->Z, &r->Z );
  /* Y3 = E*(D-X3)-8*C */
  at_bn254_fp_sub( &r->Y, d, &r->X );
  at_bn254_fp_mul( &r->Y, e, &r->Y );
  at_bn254_fp_add( c, c, c ); /* 2*c */
  at_bn254_fp_add( c, c, c ); /* 4*y */
  at_bn254_fp_add( c, c, c ); /* 8*y */
  at_bn254_fp_sub( &r->Y, &r->Y, c );
  return r;
}

/* at_bn254_g1_add_mixed computes r = p + q, when q->Z==1.
   http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl */
at_bn254_g1_t *
at_bn254_g1_add_mixed( at_bn254_g1_t *       r,
                       at_bn254_g1_t const * p,
                       at_bn254_g1_t const * q ) {
  /* p==0, return q */
  if( AT_UNLIKELY( at_bn254_g1_is_zero( p ) ) ) {
    return at_bn254_g1_set( r, q );
  }
  at_bn254_fp_t zz[1], u2[1], s2[1];
  at_bn254_fp_t h[1], hh[1];
  at_bn254_fp_t i[1], j[1];
  at_bn254_fp_t rr[1], v[1];
  /* Z1Z1 = Z1^2 */
  at_bn254_fp_sqr( zz, &p->Z );
  /* U2 = X2*Z1Z1 */
  at_bn254_fp_mul( u2, &q->X, zz );
  /* S2 = Y2*Z1*Z1Z1 */
  at_bn254_fp_mul( s2, &q->Y, &p->Z );
  at_bn254_fp_mul( s2, s2, zz );

  /* if p==q, call at_bn254_g1_dbl */
  if( AT_UNLIKELY( at_bn254_fp_eq( u2, &p->X ) && at_bn254_fp_eq( s2, &p->Y ) ) ) {
    /* COV: this may never happen with real data */
    return at_bn254_g1_dbl( r, p );
  }

  /* H = U2-X1 */
  at_bn254_fp_sub( h, u2, &p->X );
  /* HH = H^2 */
  at_bn254_fp_sqr( hh, h );
  /* I = 4*HH */
  at_bn254_fp_add( i, hh, hh );
  at_bn254_fp_add( i, i, i );
  /* J = H*I */
  at_bn254_fp_mul( j, h, i );
  /* r = 2*(S2-Y1) */
  at_bn254_fp_sub( rr, s2, &p->Y );
  at_bn254_fp_add( rr, rr, rr );
  /* V = X1*I */
  at_bn254_fp_mul( v, &p->X, i );
  /* X3 = r^2-J-2*V */
  at_bn254_fp_sqr( &r->X, rr );
  at_bn254_fp_sub( &r->X, &r->X, j );
  at_bn254_fp_sub( &r->X, &r->X, v );
  at_bn254_fp_sub( &r->X, &r->X, v );
  /* Y3 = r*(V-X3)-2*Y1*J
     note: i no longer used */
  at_bn254_fp_mul( i, &p->Y, j ); /* i =   Y1*J */
  at_bn254_fp_add( i, i, i );     /* i = 2*Y1*J */
  at_bn254_fp_sub( &r->Y, v, &r->X );
  at_bn254_fp_mul( &r->Y, &r->Y, rr );
  at_bn254_fp_sub( &r->Y, &r->Y, i );
  /* Z3 = (Z1+H)^2-Z1Z1-HH */
  at_bn254_fp_add( &r->Z, &p->Z, h );
  at_bn254_fp_sqr( &r->Z, &r->Z );
  at_bn254_fp_sub( &r->Z, &r->Z, zz );
  at_bn254_fp_sub( &r->Z, &r->Z, hh );
  return r;
}

/* at_bn254_g1_scalar_mul computes r = s * p.
   This assumes that p is affine, i.e. p->Z==1. */
at_bn254_g1_t *
at_bn254_g1_scalar_mul( at_bn254_g1_t *           r,
                        at_bn254_g1_t const *     p,
                        at_bn254_scalar_t const * s ) {
  /* TODO: wNAF, GLV */
  int i = 255;
  for( ; i>=0 && !at_uint256_bit( s, i ); i-- ) ; /* do nothing, just i-- */
  if( AT_UNLIKELY( i<0 ) ) {
    return at_bn254_g1_set_zero( r );
  }
  at_bn254_g1_set( r, p );
  for( i--; i>=0; i-- ) {
    at_bn254_g1_dbl( r, r );
    if( at_uint256_bit( s, i ) ) {
      at_bn254_g1_add_mixed( r, r, p );
    }
  }
  return r;
}

/* at_bn254_g1_frombytes_internal extracts (x, y) and performs basic checks.
   This is used by at_bn254_g1_compress() and at_bn254_g1_frombytes_check_subgroup().
   https://github.com/arkworks-rs/algebra/blob/v0.4.2/ec/src/models/short_weierstrass/mod.rs#L173-L178 */
static inline at_bn254_g1_t *
at_bn254_g1_frombytes_internal( at_bn254_g1_t * p,
                                uchar const     in[64],
                                int             big_endian ) {
  /* Special case: all zeros => point at infinity */
  const uchar zero[64] = { 0 };
  if( AT_UNLIKELY( at_memeq( in, zero, 64 ) ) ) {
    return at_bn254_g1_set_zero( p );
  }

  /* Check x < p */
  if( AT_UNLIKELY( !at_bn254_fp_frombytes_nm( &p->X, &in[0], big_endian, NULL, NULL ) ) ) {
    return NULL;
  }

  /* Check flags and y < p */
  int is_inf, is_neg;
  if( AT_UNLIKELY( !at_bn254_fp_frombytes_nm( &p->Y, &in[32], big_endian, &is_inf, &is_neg ) ) ) {
    return NULL;
  }

  if( AT_UNLIKELY( is_inf ) ) {
    return at_bn254_g1_set_zero( p );
  }

  at_bn254_fp_set_one( &p->Z );
  return p;
}

/* at_bn254_g1_frombytes_check_subgroup performs frombytes AND checks subgroup membership. */
static inline at_bn254_g1_t *
at_bn254_g1_frombytes_check_subgroup( at_bn254_g1_t * p,
                                      uchar const     in[64],
                                      int             big_endian ) {
  if( AT_UNLIKELY( !at_bn254_g1_frombytes_internal( p, in, big_endian ) ) ) {
    return NULL;
  }
  if( AT_UNLIKELY( at_bn254_g1_is_zero( p ) ) ) {
    return p;
  }

  at_bn254_fp_to_mont( &p->X, &p->X );
  at_bn254_fp_to_mont( &p->Y, &p->Y );
  at_bn254_fp_set_one( &p->Z );

  /* Check that y^2 = x^3 + b */
  at_bn254_fp_t y2[1], x3b[1];
  at_bn254_fp_sqr( y2, &p->Y );
  at_bn254_fp_sqr( x3b, &p->X );
  at_bn254_fp_mul( x3b, x3b, &p->X );
  at_bn254_fp_add( x3b, x3b, at_bn254_const_b_mont );
  if( AT_UNLIKELY( !at_bn254_fp_eq( y2, x3b ) ) ) {
    return NULL;
  }

  /* G1 has prime order, so we don't need to do any further checks. */

  return p;
}