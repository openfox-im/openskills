#include "at/crypto/at_human_readable_proof.h"

static inline ushort
hrp_be16_to_native( uchar const * p ) {
  return (ushort)( ((ushort)p[0] << 8) | (ushort)p[1] );
}

static inline ulong
hrp_be64_to_native( uchar const * p ) {
  return (ulong)( ((ulong)p[0] << 56) | ((ulong)p[1] << 48) |
                  ((ulong)p[2] << 40) | ((ulong)p[3] << 32) |
                  ((ulong)p[4] << 24) | ((ulong)p[5] << 16) |
                  ((ulong)p[6] << 8)  |  (ulong)p[7] );
}

static inline void
hrp_native_to_be16( ushort v, uchar * p ) {
  p[0] = (uchar)(v >> 8);
  p[1] = (uchar)(v);
}

static inline void
hrp_native_to_be64( ulong v, uchar * p ) {
  p[0] = (uchar)(v >> 56);
  p[1] = (uchar)(v >> 48);
  p[2] = (uchar)(v >> 40);
  p[3] = (uchar)(v >> 32);
  p[4] = (uchar)(v >> 24);
  p[5] = (uchar)(v >> 16);
  p[6] = (uchar)(v >> 8);
  p[7] = (uchar)(v);
}

int
at_human_proof_pack( uchar *                           out,
                     ulong *                           out_sz,
                     at_human_readable_proof_t const * proof ) {
  if( !out || !out_sz || !proof ) return -1;
  if( proof->proof_sz > AT_HUMAN_PROOF_MAX_BYTES ) return -1;
  if( !(proof->kind==AT_HUMAN_PROOF_KIND_BALANCE || proof->kind==AT_HUMAN_PROOF_KIND_OWNERSHIP) ) return -1;

  ulong need = 1UL + 2UL + (ulong)proof->proof_sz + 32UL + 8UL;
  if( *out_sz < need ) return -1;

  ulong off = 0;
  out[off++] = proof->kind;
  hrp_native_to_be16( proof->proof_sz, out + off ); off += 2;
  if( proof->proof_sz ) {
    at_memcpy( out + off, proof->proof, proof->proof_sz );
    off += proof->proof_sz;
  }
  at_memcpy( out + off, proof->asset, 32 ); off += 32;
  hrp_native_to_be64( proof->topoheight, out + off ); off += 8;

  *out_sz = off;
  return 0;
}

int
at_human_proof_unpack( at_human_readable_proof_t * out,
                       uchar const *               in,
                       ulong                       in_sz ) {
  if( !out || !in ) return -1;
  if( in_sz < 1UL + 2UL + 32UL + 8UL ) return -1;

  ulong off = 0;
  uchar kind = in[off++];
  if( !(kind==AT_HUMAN_PROOF_KIND_BALANCE || kind==AT_HUMAN_PROOF_KIND_OWNERSHIP) ) return -1;
  ushort proof_sz = hrp_be16_to_native( in + off ); off += 2;
  if( proof_sz > AT_HUMAN_PROOF_MAX_BYTES ) return -1;

  ulong need = 1UL + 2UL + (ulong)proof_sz + 32UL + 8UL;
  if( in_sz != need ) return -1;

  at_memset( out, 0, sizeof(*out) );
  out->kind = kind;
  out->proof_sz = proof_sz;
  if( proof_sz ) {
    at_memcpy( out->proof, in + off, proof_sz );
    off += proof_sz;
  }
  at_memcpy( out->asset, in + off, 32 ); off += 32;
  out->topoheight = hrp_be64_to_native( in + off ); off += 8;
  return 0;
}

int
at_human_proof_as_string( char *                            out,
                          ulong                             out_sz,
                          at_human_readable_proof_t const * proof ) {
  if( !out || !proof ) return -1;

  uchar packed[1 + 2 + AT_HUMAN_PROOF_MAX_BYTES + 32 + 8];
  ulong packed_sz = sizeof(packed);
  if( at_human_proof_pack( packed, &packed_sz, proof ) ) return -1;

  uchar data5[4096];
  ulong data5_sz = sizeof(data5);
  if( at_bech32_convert_bits( data5, &data5_sz, 5, packed, packed_sz, 8, 1 ) != AT_BECH32_OK ) {
    return -1;
  }

  int enc_sz = at_bech32_encode( out, out_sz, AT_HUMAN_PROOF_PREFIX, data5, data5_sz );
  return enc_sz >= 0 ? 0 : -1;
}

int
at_human_proof_from_string( at_human_readable_proof_t * out,
                            char const *                s ) {
  if( !out || !s ) return -1;

  char hrp[64];
  uchar data5[4096];
  ulong data5_sz = sizeof(data5);
  if( at_bech32_decode( s, hrp, sizeof(hrp), data5, &data5_sz ) != AT_BECH32_OK ) return -1;
  if( at_strcmp( hrp, AT_HUMAN_PROOF_PREFIX ) ) return -1;

  uchar data8[1 + 2 + AT_HUMAN_PROOF_MAX_BYTES + 32 + 8];
  ulong data8_sz = sizeof(data8);
  if( at_bech32_convert_bits( data8, &data8_sz, 8, data5, data5_sz, 5, 0 ) != AT_BECH32_OK ) {
    return -1;
  }

  return at_human_proof_unpack( out, data8, data8_sz );
}
