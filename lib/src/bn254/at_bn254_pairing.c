#include "at_bn254.h"

/* Pairing */

static inline void
at_bn254_pairing_proj_dbl( at_bn254_fp12_t *     r,
                           at_bn254_g2_t *       t,
                           at_bn254_g1_t const * p ) {
  /* https://eprint.iacr.org/2012/408, Sec 4.2.
     See also: https://eprint.iacr.org/2013/722, Sec. 4.3, Eq. (11).
     https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/pairing.go#L302
     Note: this can be optimized by precomputing 3x, -y and probably more. */
  at_bn254_fp2_t * X = &t->X;
  at_bn254_fp2_t * Y = &t->Y;
  at_bn254_fp2_t * Z = &t->Z;
  at_bn254_fp_t const * x = &p->X;
  at_bn254_fp_t const * y = &p->Y;
  at_bn254_fp2_t a[1], b[1], c[1], d[1];
  at_bn254_fp2_t e[1], f[1], g[1], h[1];
  at_bn254_fp_t x3[1];
  /* A=X1*Y1/2 */
  at_bn254_fp2_mul( a, X, Y );
  at_bn254_fp2_halve( a, a );
  /* B=Y1^2 */
  at_bn254_fp2_sqr( b, Y );
  /* C=Z1^2 */
  at_bn254_fp2_sqr( c, Z );
  /* D=3C */
  at_bn254_fp2_add( d, c, c );
  at_bn254_fp2_add( d, d, c );
  /* E=b'*D */
  at_bn254_fp2_mul( e, d, at_bn254_const_twist_b_mont );
  /* F=3E */
  at_bn254_fp2_add( f, e, e );
  at_bn254_fp2_add( f, f, e );
  /* G=(B+F)/2 */
  at_bn254_fp2_add( g, b, f );
  at_bn254_fp2_halve( g, g );
  /* H =(Y1+Z1)^2 − (B+C) */
  at_bn254_fp2_add( h, Y, Z );
  at_bn254_fp2_sqr( h, h );
  at_bn254_fp2_sub( h, h, b );
  at_bn254_fp2_sub( h, h, c );

  /* g(P) = (H * -y) + (X^2 * 3 * x)w + (E−B)w^3. */
  /* el[0][0] = -(H * y) */
  at_bn254_fp2_neg( &r->el[0].el[0], h );
  at_bn254_fp_mul( &r->el[0].el[0].el[0], &r->el[0].el[0].el[0], y );
  at_bn254_fp_mul( &r->el[0].el[0].el[1], &r->el[0].el[0].el[1], y );
  /* el[0][1] = 0 */
  at_bn254_fp2_set_zero( &r->el[0].el[1] );
  /* el[0][2] = 0 */
  at_bn254_fp2_set_zero( &r->el[0].el[2] );
  /* el[1][0] = (3 * X^2 * x) */
  at_bn254_fp2_sqr( &r->el[1].el[0], X );
  at_bn254_fp_add( x3, x, x );
  at_bn254_fp_add( x3, x3, x );
  at_bn254_fp_mul( &r->el[1].el[0].el[0], &r->el[1].el[0].el[0], x3 );
  at_bn254_fp_mul( &r->el[1].el[0].el[1], &r->el[1].el[0].el[1], x3 );
  /* el[1][0] = (E−B) */
  at_bn254_fp2_sub( &r->el[1].el[1], e, b );
  /* el[1][2] = 0 */
  at_bn254_fp2_set_zero( &r->el[1].el[2] );

  /* update t */
  /* X3 = A * (B−F) */
  at_bn254_fp2_sub( X, b, f );
  at_bn254_fp2_mul( X, X, a );
  /* Y3 = G^2 − 3*E^2 (reusing var c, d) */
  at_bn254_fp2_sqr( Y, g );
  at_bn254_fp2_sqr( c, e );
  at_bn254_fp2_add( d, c, c );
  at_bn254_fp2_add( d, d, c );
  at_bn254_fp2_sub( Y, Y, d );
  /* Z3 = B * H */
  at_bn254_fp2_mul( Z, b, h );
}

static inline void
at_bn254_pairing_proj_add_sub( at_bn254_fp12_t *     r,
                               at_bn254_g2_t *       t,
                               at_bn254_g2_t const * q,
                               at_bn254_g1_t const * p,
                               int                   is_add,
                               int                   add_point ) {
  /* https://eprint.iacr.org/2012/408, Sec 4.2.
     See also: https://eprint.iacr.org/2013/722, Sec. 4.3, Eq. (12, 13).
     https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/pairing.go#L343
     Note: this can be optimized by precomputing -x and probably more. */
  at_bn254_fp2_t * X = &t->X;
  at_bn254_fp2_t * Y = &t->Y;
  at_bn254_fp2_t * Z = &t->Z;
  at_bn254_fp2_t const * X2 = &q->X;
  at_bn254_fp2_t Y2[1];
  at_bn254_fp_t const * x = &p->X;
  at_bn254_fp_t const * y = &p->Y;
  at_bn254_fp2_t a[1], b[1], c[1], d[1];
  at_bn254_fp2_t e[1], f[1], g[1], h[1];
  at_bn254_fp2_t i[1], j[1], k[1];
  at_bn254_fp2_t o[1], l[1];

  if( is_add ) {
    at_bn254_fp2_set( Y2, &q->Y );
  } else {
    at_bn254_fp2_neg( Y2, &q->Y );
  }

  at_bn254_fp2_mul( a, Y2, Z );
  at_bn254_fp2_mul( b, X2, Z );
  at_bn254_fp2_sub( o, Y, a );
  at_bn254_fp2_sub( l, X, b );

  at_bn254_fp2_mul( j, o, X2 );
  at_bn254_fp2_mul( k, l, Y2 );
  // at_bn254_fp2_sub( j, j, k );

  /* g(P) */
  /* el[0][0] = (l * y) */
  at_bn254_fp_mul( &r->el[0].el[0].el[0], &l->el[0], y );
  at_bn254_fp_mul( &r->el[0].el[0].el[1], &l->el[1], y );
  /* el[0][1] = 0 */
  at_bn254_fp2_set_zero( &r->el[0].el[1] );
  /* el[0][2] = 0 */
  at_bn254_fp2_set_zero( &r->el[0].el[2] );
  /* el[1][0] = -(o * x), term in w */
  at_bn254_fp2_neg( &r->el[1].el[0], o );
  at_bn254_fp_mul( &r->el[1].el[0].el[0], &r->el[1].el[0].el[0], x );
  at_bn254_fp_mul( &r->el[1].el[0].el[1], &r->el[1].el[0].el[1], x );
  /* el[1][1] = j-k */
  at_bn254_fp2_sub( &r->el[1].el[1], j, k );
  /* el[1][2] = 0 */
  at_bn254_fp2_set_zero( &r->el[1].el[2] );

  if( add_point ) {
    at_bn254_fp2_sqr( c, o );
    at_bn254_fp2_sqr( d, l );
    at_bn254_fp2_mul( e, d, l );
    at_bn254_fp2_mul( f, Z, c );
    at_bn254_fp2_mul( g, X, d );
    at_bn254_fp2_add( h, e, f );
    at_bn254_fp2_sub( h, h, g );
    at_bn254_fp2_sub( h, h, g );
    at_bn254_fp2_mul( i, Y, e );

    /* update t */
    at_bn254_fp2_mul( X, l, h );
    at_bn254_fp2_sub( Y, g, h );
    at_bn254_fp2_mul( Y, Y, o );
    at_bn254_fp2_sub( Y, Y, i );
    at_bn254_fp2_mul( Z, Z, e );
  }
}

at_bn254_fp12_t *
at_bn254_miller_loop( at_bn254_fp12_t *   f,
                      at_bn254_g1_t const p[],
                      at_bn254_g2_t const q[],
                      ulong               sz ) {
  /* https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/pairing.go#L121 */
  //TODO use more efficient muls
  const schar s[] = {
    0,  0,  0,  1,  0,  1,  0, -1,
    0,  0, -1,  0,  0,  0,  1,  0,
    0, -1,  0, -1,  0,  0,  0,  1,
    0, -1,  0,  0,  0,  0, -1,  0,
    0,  1,  0, -1,  0,  0,  1,  0,
    0,  0,  0,  0, -1,  0,  0, -1,
    0,  1,  0, -1,  0,  0,  0, -1,
    0, -1,  0,  0,  0,  1,  0, -1, /* 0, 1 */
  };

  at_bn254_g2_t t[AT_BN254_PAIRING_BATCH_MAX], frob[1];
  at_bn254_fp12_t l[1];

  at_bn254_fp12_set_one( f );
  for ( ulong j=0; j<sz; j++ ) {
    at_bn254_g2_set( &t[j], &q[j] );
  }

  for( ulong j=0; j<sz; j++ ) {
    at_bn254_pairing_proj_dbl( l, &t[j], &p[j] );
    at_bn254_fp12_mul( f, f, l );
  }
  at_bn254_fp12_sqr( f, f );

  for( ulong j=0; j<sz; j++ ) {
    at_bn254_pairing_proj_add_sub( l, &t[j], &q[j], &p[j], 0, 0 ); /* do not change t */
    at_bn254_fp12_mul( f, f, l );

    at_bn254_pairing_proj_add_sub( l, &t[j], &q[j], &p[j], 1, 1 );
    at_bn254_fp12_mul( f, f, l );
  }

  for( int i = 65-3; i>=0; i-- ) {
    at_bn254_fp12_sqr( f, f );

    for( ulong j=0; j<sz; j++ ) {
      at_bn254_pairing_proj_dbl( l, &t[j], &p[j] );
      at_bn254_fp12_mul( f, f, l );
    }

    if( s[i] != 0 ) {
      for( ulong j=0; j<sz; j++ ) {
        at_bn254_pairing_proj_add_sub( l, &t[j], &q[j], &p[j], s[i] > 0, 1 );
        at_bn254_fp12_mul( f, f, l );
      }
    }
  }

  for( ulong j=0; j<sz; j++ ) {
    at_bn254_g2_frob( frob, &q[j] ); /* frob(q) */
    at_bn254_pairing_proj_add_sub( l, &t[j], frob, &p[j], 1, 1 );
    at_bn254_fp12_mul( f, f, l );

    at_bn254_g2_frob2( frob, &q[j] ); /* -frob^2(q) */
    at_bn254_g2_neg( frob, frob );
    at_bn254_pairing_proj_add_sub( l, &t[j], frob, &p[j], 1, 0 ); /* do not change t */
    at_bn254_fp12_mul( f, f, l );
  }
  return f;
}

at_bn254_fp12_t *
at_bn254_fp12_pow_x( at_bn254_fp12_t * restrict r,
                     at_bn254_fp12_t const *    a ) {
  /* https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/internal/fptower/e12_pairing.go#L16 */
  at_bn254_fp12_t t[7];
  at_bn254_fp12_sqr_fast( &t[3], a );
  at_bn254_fp12_sqr_fast( &t[5], &t[3] );
  at_bn254_fp12_sqr_fast( r,     &t[5] );
  at_bn254_fp12_sqr_fast( &t[0], r );
  at_bn254_fp12_mul     ( &t[2], &t[0], a );
  at_bn254_fp12_mul     ( &t[0], &t[2], &t[3] );
  at_bn254_fp12_mul     ( &t[1], &t[0], a );
  at_bn254_fp12_mul     ( &t[4], &t[2], r );
  at_bn254_fp12_sqr_fast( &t[6], &t[2] );
  at_bn254_fp12_mul     ( &t[1], &t[1], &t[0] );
  at_bn254_fp12_mul     ( &t[0], &t[1], &t[3] );
  for( int i=0; i<6; i++ ) at_bn254_fp12_sqr_fast( &t[6], &t[6] );
  at_bn254_fp12_mul     ( &t[5], &t[5], &t[6] );
  at_bn254_fp12_mul     ( &t[5], &t[5], &t[4] );
  for( int i=0; i<7; i++ ) at_bn254_fp12_sqr_fast( &t[5], &t[5] );
  at_bn254_fp12_mul     ( &t[4], &t[4], &t[5] );
  for( int i=0; i<8; i++ ) at_bn254_fp12_sqr_fast( &t[4], &t[4] );
  at_bn254_fp12_mul     ( &t[4], &t[4], &t[0] );
  at_bn254_fp12_mul     ( &t[3], &t[3], &t[4] );
  for( int i=0; i<6; i++ ) at_bn254_fp12_sqr_fast( &t[3], &t[3] );
  at_bn254_fp12_mul     ( &t[2], &t[2], &t[3] );
  for( int i=0; i<8; i++ ) at_bn254_fp12_sqr_fast( &t[2], &t[2] );
  at_bn254_fp12_mul     ( &t[2], &t[2], &t[0] );
  for( int i=0; i<6; i++ ) at_bn254_fp12_sqr_fast( &t[2], &t[2] );
  at_bn254_fp12_mul     ( &t[2], &t[2], &t[0] );
  for( int i=0; i<10; i++ ) at_bn254_fp12_sqr_fast( &t[2], &t[2] );
  at_bn254_fp12_mul     ( &t[1], &t[1], &t[2] );
  for( int i=0; i<6; i++ ) at_bn254_fp12_sqr_fast( &t[1], &t[1] );
  at_bn254_fp12_mul     ( &t[0], &t[0], &t[1] );
  at_bn254_fp12_mul     ( r, r, &t[0] );
  return r;
}

at_bn254_fp12_t *
at_bn254_final_exp( at_bn254_fp12_t *       r,
                    at_bn254_fp12_t * const x ) {
  /* https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/pairing.go#L62 */
  at_bn254_fp12_t t[5], s[1];
  at_bn254_fp12_conj ( &t[0], x );            /* x^(p^6) */
  at_bn254_fp12_inv  ( &t[1], x );            /* x^(-1) */
  at_bn254_fp12_mul  ( &t[0], &t[0], &t[1] ); /* x^(p^6-1) */
  at_bn254_fp12_frob2( &t[2], &t[0] );        /* x^(p^6-1)(p^2) */
  at_bn254_fp12_mul  ( s, &t[0], &t[2] );     /* x^(p^6-1)(p^2+1) */
  /* Fast chain, https://eprint.iacr.org/2015/192, Alg. 10.
     Variant of https://eprint.iacr.org/2010/354, Alg. 31. */
  at_bn254_fp12_pow_x   ( &t[0], s );
  at_bn254_fp12_conj    ( &t[0], &t[0] );
  at_bn254_fp12_sqr_fast( &t[0], &t[0] );
  at_bn254_fp12_sqr_fast( &t[1], &t[0] );
  at_bn254_fp12_mul     ( &t[1], &t[1], &t[0] );

  at_bn254_fp12_pow_x   ( &t[2], &t[1] );
  at_bn254_fp12_conj    ( &t[2], &t[2] );
  at_bn254_fp12_conj    ( &t[3], &t[1] );
  at_bn254_fp12_mul     ( &t[1], &t[2], &t[3] );

  at_bn254_fp12_sqr_fast( &t[3], &t[2] );
  at_bn254_fp12_pow_x   ( &t[4], &t[3] );
  at_bn254_fp12_mul     ( &t[4], &t[1], &t[4] );
  at_bn254_fp12_mul     ( &t[3], &t[0], &t[4] );
  at_bn254_fp12_mul     ( &t[0], &t[2], &t[4] );
  at_bn254_fp12_mul     ( &t[0], &t[0], s );

  at_bn254_fp12_frob    ( &t[2], &t[3] );
  at_bn254_fp12_mul     ( &t[0], &t[0], &t[2] );
  at_bn254_fp12_frob2   ( &t[2], &t[4] );
  at_bn254_fp12_mul     ( &t[0], &t[0], &t[2] );

  at_bn254_fp12_conj    ( &t[2], s );
  at_bn254_fp12_mul     ( &t[2], &t[2], &t[3] );
  // at_bn254_fp12_frob3   ( &t[2], &t[2] );
  at_bn254_fp12_frob2   ( &t[2], &t[2] );
  at_bn254_fp12_frob    ( &t[2], &t[2] );
  at_bn254_fp12_mul     ( r, &t[0], &t[2] );
  return r;
}