/* at_vrf.c - VRF (Verifiable Random Function) implementation

   This implements schnorrkel-compatible VRF using DLEQ proofs over Ristretto255.
   Fully compatible with TOS VRF using domain separator "TOS-VRF-v1".

   Algorithm based on schnorrkel 0.11.x:
   1. Key expansion: MiniSecretKey.expand_to_keypair(Ed25519) with cofactor division
   2. VRF hash: Merlin transcript -> 64 bytes -> RistrettoPoint::from_uniform_bytes
   3. DLEQ proof: Schnorr-style proof of discrete log equality */

#include <at/crypto/at_vrf.h>
#include <at/crypto/at_merlin.h>
#include <at/crypto/at_ristretto255.h>
#include <at/crypto/at_curve25519_scalar.h>

#include <string.h>
#include <stdio.h>


/* Divide scalar by 8 (cofactor).
   This is needed for schnorrkel Ed25519 expansion mode. */
static void
scalar_divide_by_8( uchar out[32], uchar const in[32] ) {
  /* Shift right by 3 bits */
  uchar carry = 0;
  for( int i = 31; i >= 0; i-- ) {
    uchar next_carry = (in[i] & 0x07) << 5;
    out[i] = (in[i] >> 3) | carry;
    carry = next_carry;
  }
}

/* Merlin transcript: append_message with length encoding */
static void
merlin_append_message( at_merlin_transcript_t * t,
                       char const *             label,
                       uint                     label_len,
                       uchar const *            message,
                       uint                     message_len ) {
  at_merlin_transcript_append_message( t, label, label_len, message, message_len );
}

/* Merlin transcript: commit a point (compressed Ristretto) */
static void
merlin_commit_point( at_merlin_transcript_t * t,
                     char const *             label,
                     uint                     label_len,
                     uchar const              point[32] ) {
  at_merlin_transcript_append_message( t, label, label_len, point, 32 );
}

/* Merlin transcript: get challenge bytes */
static void
merlin_challenge_bytes( at_merlin_transcript_t * t,
                        char const *             label,
                        uint                     label_len,
                        uchar *                  out,
                        uint                     out_len ) {
  at_merlin_transcript_challenge_bytes( t, label, label_len, out, out_len );
}

/* Initialize VRF input transcript (SigningContext + input) */
static void
vrf_input_transcript_init( at_merlin_transcript_t * t,
                           uchar const *            input,
                           ulong                    input_sz ) {
  /* schnorrkel: Transcript::new(b"SigningContext") */
  at_merlin_transcript_init( t, AT_MERLIN_LITERAL("SigningContext") );

  /* schnorrkel: append_message(b"", context) where context = "TOS-VRF-v1" */
  merlin_append_message( t, "", 0,
                         (uchar const *)AT_VRF_TOS_CONTEXT,
                         AT_VRF_TOS_CONTEXT_SZ );

  /* schnorrkel: append_message(b"sign-bytes", input) */
  merlin_append_message( t, AT_MERLIN_LITERAL("sign-bytes"), input, (uint)input_sz );
}

/* Hash transcript to Ristretto point using from_uniform_bytes */
static void
vrf_hash_to_point( at_ristretto255_point_t *  point,
                   at_merlin_transcript_t *   t ) {
  /* schnorrkel: challenge_bytes(b"VRFHash", 64 bytes) */
  uchar hash_bytes[64];
  merlin_challenge_bytes( t, AT_MERLIN_LITERAL("VRFHash"), hash_bytes, 64 );

  /* Convert 64 uniform bytes to Ristretto point */
  at_ristretto255_hash_to_curve( point, hash_bytes );
}

/* Initialize DLEQ proof transcript */
static void
dleq_proof_transcript_init( at_merlin_transcript_t * t ) {
  /* schnorrkel: Transcript::new(b"VRF") then proto_name(b"DLEQProof") */
  at_merlin_transcript_init( t, AT_MERLIN_LITERAL("VRF") );

  /* proto_name adds protocol name to transcript */
  merlin_append_message( t, AT_MERLIN_LITERAL("proto-name"),
                         (uchar const *)"DLEQProof", 9 );
}

/* Create DLEQ proof challenge */
static void
dleq_create_challenge( uchar                            c[32],
                       at_merlin_transcript_t *         t,
                       uchar const                      H[32],
                       uchar const                      public_key[32],
                       uchar const                      R[32],
                       uchar const                      Hr[32],
                       uchar const                      output[32] ) {
  /* schnorrkel labels for DLEQ proof.
     IMPORTANT: order must match schnorrkel KUSAMA_VRF=true:
       h, R, h^r, pk, h^sk
     (pk is committed after R/h^r, not before). */
  merlin_commit_point( t, AT_MERLIN_LITERAL("vrf:h"), H );
  merlin_commit_point( t, AT_MERLIN_LITERAL("vrf:R=g^r"), R );
  merlin_commit_point( t, AT_MERLIN_LITERAL("vrf:h^r"), Hr );
  merlin_commit_point( t, AT_MERLIN_LITERAL("vrf:pk"), public_key );
  merlin_commit_point( t, AT_MERLIN_LITERAL("vrf:h^sk"), output );

  /* Get 64-byte challenge and reduce to scalar */
  uchar challenge_bytes[64];
  merlin_challenge_bytes( t, AT_MERLIN_LITERAL("prove"), challenge_bytes, 64 );
  at_curve25519_scalar_reduce( c, challenge_bytes );
}

/* Generate witness nonce from transcript and nonce seed */
static void
vrf_witness_scalar( uchar                      r[32],
                    at_merlin_transcript_t *   t,
                    uchar const                nonce_seed[32] ) {
  /* schnorrkel: witness_scalar with label "proving\0" and nonce_seed */
  merlin_append_message( t, "proving", 8, nonce_seed, 32 );

  uchar witness_bytes[64];
  merlin_challenge_bytes( t, AT_MERLIN_LITERAL("witness"), witness_bytes, 64 );
  at_curve25519_scalar_reduce( r, witness_bytes );
}

at_vrf_keypair_t *
at_vrf_keypair_from_seed( at_vrf_keypair_t * keypair,
                          uchar const        seed[32] ) {
  if( !keypair || !seed ) return NULL;

  at_memset( keypair, 0, sizeof(at_vrf_keypair_t) );

  /* Step 1: SHA-512 hash of seed */
  uchar h[64];
  at_sha512_t sha[1];
  at_sha512_fini( at_sha512_append( at_sha512_init( sha ), seed, 32 ), h );

  /* Step 2: Bit clamping (Ed25519 style) */
  h[0] &= (uchar)0xF8;   /* Clear lower 3 bits */
  h[31] &= (uchar)0x3F;  /* Clear bits 6-7 */
  h[31] |= (uchar)0x40;  /* Set bit 6 */

  /* Step 3: Divide by cofactor 8 (schnorrkel Ed25519 mode) */
  uchar key_scalar[32];
  scalar_divide_by_8( key_scalar, h );

  /* Store the scalar and nonce seed */
  at_memcpy( keypair->secret, key_scalar, 32 );
  at_memcpy( keypair->nonce, h + 32, 32 );

  /* Step 4: Compute public key = scalar * base_point */
  at_ristretto255_point_t A[1];
  at_ed25519_scalar_mul_base_const_time( A, key_scalar );
  at_ristretto255_point_tobytes( keypair->public_key, A );

  /* Clear sensitive data */
  at_memset_explicit( h, 0, 64 );
  at_memset_explicit( key_scalar, 0, 32 );
  at_sha512_clear( sha );

  return keypair;
}

uchar *
at_vrf_public_key( uchar                      public_key[32],
                   at_vrf_keypair_t const *   keypair ) {
  if( !public_key || !keypair ) return NULL;
  at_memcpy( public_key, keypair->public_key, 32 );
  return public_key;
}

int
at_vrf_sign( uchar                    output[32],
             uchar                    proof[64],
             uchar const *            input,
             ulong                    input_sz,
             at_vrf_keypair_t const * keypair ) {
  if( !output || !proof || !keypair ) return AT_VRF_ERR_PROOF;
  if( input_sz > AT_VRF_MAX_INPUT_LEN ) return AT_VRF_ERR_PROOF;
  if( input_sz > 0 && !input ) return AT_VRF_ERR_PROOF;

  /* Step 1: Create VRF input transcript */
  at_merlin_transcript_t t_input[1];
  vrf_input_transcript_init( t_input, input, input_sz );

  /* Step 2: Add public key for non-malleability (BEFORE hash!)
     schnorrkel: transcript_with_malleability_addressed appends vrf-nm-pk
     before calling vrf_malleable_hash which does challenge_bytes("VRFHash") */
  merlin_append_message( t_input, AT_MERLIN_LITERAL("vrf-nm-pk"),
                         keypair->public_key, 32 );

  /* Step 3: Hash to point H */
  at_ristretto255_point_t H[1];
  vrf_hash_to_point( H, t_input );

  /* Step 3: Compute VRF output = secret * H */
  at_ristretto255_point_t out_point[1];
  at_ristretto255_scalar_mul( out_point, keypair->secret, H );
  at_ristretto255_point_tobytes( output, out_point );

  /* Step 4: Generate DLEQ proof */

  /* 4a: Generate witness nonce r */
  at_merlin_transcript_t t_witness[1];
  at_merlin_transcript_init( t_witness, AT_MERLIN_LITERAL("VRF") );

  uchar r[32];
  vrf_witness_scalar( r, t_witness, keypair->nonce );

  /* 4b: Compute R = r * base_point */
  at_ristretto255_point_t R_point[1];
  at_ed25519_scalar_mul_base_const_time( R_point, r );
  uchar R[32];
  at_ristretto255_point_tobytes( R, R_point );

  /* 4c: Compute Hr = r * H */
  at_ristretto255_point_t Hr_point[1];
  at_ristretto255_scalar_mul( Hr_point, r, H );
  uchar Hr[32];
  at_ristretto255_point_tobytes( Hr, Hr_point );

  /* 4d: Compress H for transcript */
  uchar H_compressed[32];
  at_ristretto255_point_tobytes( H_compressed, H );

  /* 4e: Create challenge c */
  at_merlin_transcript_t t_proof[1];
  dleq_proof_transcript_init( t_proof );

  uchar c[32];
  dleq_create_challenge( c, t_proof, H_compressed, keypair->public_key,
                         R, Hr, output );

  /* 4f: Compute s = r - c * secret (mod L) */
  uchar c_secret[32];
  at_curve25519_scalar_mul( c_secret, c, keypair->secret );

  uchar s[32];
  at_curve25519_scalar_sub( s, r, c_secret );

  /* Store proof: (c, s) */
  at_memcpy( proof, c, 32 );
  at_memcpy( proof + 32, s, 32 );

  /* Clear sensitive data */
  at_memset_explicit( r, 0, 32 );
  at_memset_explicit( c_secret, 0, 32 );

  return AT_VRF_SUCCESS;
}

int
at_vrf_verify( uchar const * input,
               ulong         input_sz,
               uchar const   output[32],
               uchar const   proof[64],
               uchar const   public_key[32] ) {
  if( input_sz > AT_VRF_MAX_INPUT_LEN ) return AT_VRF_ERR_VERIFY;
  if( input_sz > 0 && !input ) return AT_VRF_ERR_VERIFY;
  if( !output || !proof || !public_key ) return AT_VRF_ERR_VERIFY;

  /* Parse proof: (c, s) */
  uchar const * c = proof;
  uchar const * s = proof + 32;

  /* Validate scalars */
  if( !at_curve25519_scalar_validate( c ) ) return AT_VRF_ERR_PROOF;
  if( !at_curve25519_scalar_validate( s ) ) return AT_VRF_ERR_PROOF;

  /* Decompress public key */
  at_ristretto255_point_t A[1];
  if( !at_ristretto255_point_frombytes( A, public_key ) ) {
    return AT_VRF_ERR_PUBKEY;
  }

  /* Decompress VRF output */
  at_ristretto255_point_t out_point[1];
  if( !at_ristretto255_point_frombytes( out_point, output ) ) {
    return AT_VRF_ERR_OUTPUT;
  }

  /* Step 1: Recreate VRF input transcript */
  at_merlin_transcript_t t_input[1];
  vrf_input_transcript_init( t_input, input, input_sz );

  /* Step 2: Add public key for non-malleability (BEFORE hash!)
     schnorrkel: transcript_with_malleability_addressed appends vrf-nm-pk
     before calling vrf_malleable_hash which does challenge_bytes("VRFHash") */
  merlin_append_message( t_input, AT_MERLIN_LITERAL("vrf-nm-pk"),
                         public_key, 32 );

  /* Step 3: Hash to point H */
  at_ristretto255_point_t H[1];
  vrf_hash_to_point( H, t_input );

  /* Step 3: Reconstruct R = c*A + s*G (where G is base point) */
  at_ristretto255_point_t R_point[1];
  at_ed25519_double_scalar_mul_base( R_point, c, A, s );
  uchar R[32];
  at_ristretto255_point_tobytes( R, R_point );

  /* Step 4: Reconstruct Hr = c*output + s*H */
  at_ristretto255_point_t c_out[1], s_H[1], Hr_point[1];
  at_ristretto255_scalar_mul( c_out, c, out_point );
  at_ristretto255_scalar_mul( s_H, s, H );
  at_ristretto255_point_add( Hr_point, c_out, s_H );
  uchar Hr[32];
  at_ristretto255_point_tobytes( Hr, Hr_point );

  /* Step 5: Compress H for transcript */
  uchar H_compressed[32];
  at_ristretto255_point_tobytes( H_compressed, H );

  /* Step 6: Recreate challenge c' */
  at_merlin_transcript_t t_proof[1];
  dleq_proof_transcript_init( t_proof );

  uchar c_check[32];
  dleq_create_challenge( c_check, t_proof, H_compressed, public_key,
                         R, Hr, output );

  /* Step 7: Verify c == c' */
  if( !at_memeq( c, c_check, 32 ) ) {
    return AT_VRF_ERR_VERIFY;
  }

  return AT_VRF_SUCCESS;
}

char const *
at_vrf_strerror( int err ) {
  switch( err ) {
  case AT_VRF_SUCCESS:    return "success";
  case AT_VRF_ERR_PUBKEY: return "invalid public key";
  case AT_VRF_ERR_PROOF:  return "invalid proof";
  case AT_VRF_ERR_OUTPUT: return "invalid output";
  case AT_VRF_ERR_VERIFY: return "verification failed";
  default: break;
  }
  return "unknown error";
}
