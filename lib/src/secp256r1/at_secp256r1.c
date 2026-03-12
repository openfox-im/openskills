#include "at_secp256r1_private.h"

int
at_secp256r1_verify( uchar const   msg[], /* msg_sz */
                     ulong         msg_sz,
                     uchar const   sig[ 64 ],
                     uchar const   public_key[ 33 ],
                     at_sha256_t * sha ) {
  at_secp256r1_scalar_t r[1], s[1], u1[1], u2[1];
  at_secp256r1_point_t pub[1], Rcmp[1];

  /* Deserialize signature.
     Note: we enforce 0 < r < n, 0 < s <= (n-1)/2.
     The condition on s is required to avoid signature malleability. */
  if( AT_UNLIKELY( !at_secp256r1_scalar_frombytes( r, sig ) ) ) {
    return AT_SECP256R1_FAILURE;
  }
  if( AT_UNLIKELY( !at_secp256r1_scalar_frombytes_positive( s, sig+32 ) ) ) {
    return AT_SECP256R1_FAILURE;
  }
  if( AT_UNLIKELY( at_secp256r1_scalar_is_zero( r ) || at_secp256r1_scalar_is_zero( s ) ) ) {
    return AT_SECP256R1_FAILURE;
  }

  /* Deserialize public key. */
  if( AT_UNLIKELY( !at_secp256r1_point_frombytes( pub, public_key ) ) ) {
    return AT_SECP256R1_FAILURE;
  }

  /* Hash message. */
  uchar hash[ AT_SHA256_HASH_SZ ];
  at_sha256_fini( at_sha256_append( at_sha256_init( sha ), msg, msg_sz ), hash );
  at_secp256r1_scalar_from_digest( u1, hash );

  /* ECDSA sig verify. */
  at_secp256r1_scalar_inv( s, s );
  at_secp256r1_scalar_mul( u1, u1, s );
  at_secp256r1_scalar_mul( u2, r, s );
  at_secp256r1_double_scalar_mul_base( Rcmp, u1, pub, u2 );
  if( AT_LIKELY( at_secp256r1_point_eq_x( Rcmp, r ) ) ) {
    return AT_SECP256R1_SUCCESS;
  }

  return AT_SECP256R1_FAILURE;
}