#include "at/crypto/at_address.h"

int
at_address_new_normal( at_address_t * out,
                       int            mainnet,
                       uchar const    public_key[32] ) {
  if( !out || !public_key ) return -1;
  at_memset( out, 0, sizeof(*out) );
  out->mainnet = mainnet ? 1 : 0;
  out->addr_type = AT_ADDRESS_TYPE_NORMAL;
  at_memcpy( out->public_key, public_key, 32UL );
  return 0;
}

int
at_address_new_data( at_address_t * out,
                     int            mainnet,
                     uchar const    public_key[32],
                     void const *   integrated_data,
                     ulong          integrated_data_sz ) {
  if( !out || !public_key ) return -1;
  if( integrated_data_sz > AT_ADDRESS_MAX_INTEGRATED_DATA ) return -1;
  if( integrated_data_sz && !integrated_data ) return -1;

  at_memset( out, 0, sizeof(*out) );
  out->mainnet = mainnet ? 1 : 0;
  out->addr_type = integrated_data_sz ? AT_ADDRESS_TYPE_DATA : AT_ADDRESS_TYPE_NORMAL;
  at_memcpy( out->public_key, public_key, 32UL );
  if( integrated_data_sz ) {
    at_memcpy( out->integrated_data, integrated_data, integrated_data_sz );
    out->integrated_data_sz = integrated_data_sz;
  }
  return 0;
}

int
at_address_from_string( char const * s,
                        at_address_t * out ) {
  if( !s || !out ) return -1;

  char hrp[16];
  uchar data5[256];
  ulong data5_sz = sizeof(data5);
  int rc = at_bech32_decode( s, hrp, sizeof(hrp), data5, &data5_sz );
  if( rc != AT_BECH32_OK ) return -1;

  int mainnet = 0;
  if( at_strcmp( hrp, AT_BECH32_TOS_MAINNET ) == 0 ) {
    mainnet = 1;
  } else if( at_strcmp( hrp, AT_BECH32_TOS_TESTNET ) == 0 ) {
    mainnet = 0;
  } else {
    return -1;
  }

  uchar raw[256];
  ulong raw_sz = sizeof(raw);
  rc = at_bech32_convert_bits( raw, &raw_sz, 8, data5, data5_sz, 5, 0 );
  if( rc != AT_BECH32_OK ) return -1;
  if( raw_sz < 33UL ) return -1;

  uchar addr_type = raw[32];
  ulong integrated_sz = raw_sz - 33UL;
  if( addr_type > (uchar)AT_ADDRESS_TYPE_DATA ) return -1;
  if( addr_type == (uchar)AT_ADDRESS_TYPE_NORMAL && integrated_sz != 0UL ) return -1;
  if( integrated_sz > AT_ADDRESS_MAX_INTEGRATED_DATA ) return -1;

  at_memset( out, 0, sizeof(*out) );
  out->mainnet = mainnet;
  out->addr_type = (at_address_type_t)addr_type;
  at_memcpy( out->public_key, raw, 32UL );
  if( integrated_sz ) {
    at_memcpy( out->integrated_data, raw + 33UL, integrated_sz );
    out->integrated_data_sz = integrated_sz;
  }
  return 0;
}

int
at_address_as_string( at_address_t const * address,
                      char *               out,
                      ulong                out_sz ) {
  if( !address || !out ) return -1;
  if( address->integrated_data_sz > AT_ADDRESS_MAX_INTEGRATED_DATA ) return -1;
  if( address->addr_type == AT_ADDRESS_TYPE_NORMAL && address->integrated_data_sz != 0UL ) return -1;
  if( address->addr_type == AT_ADDRESS_TYPE_DATA && address->integrated_data_sz == 0UL ) return -1;

  uchar raw[33UL + AT_ADDRESS_MAX_INTEGRATED_DATA];
  ulong raw_sz = 33UL;
  at_memcpy( raw, address->public_key, 32UL );
  raw[32] = (uchar)address->addr_type;
  if( address->addr_type == AT_ADDRESS_TYPE_DATA ) {
    at_memcpy( raw + 33UL, address->integrated_data, address->integrated_data_sz );
    raw_sz += address->integrated_data_sz;
  }

  uchar data5[256];
  ulong data5_sz = sizeof(data5);
  int rc = at_bech32_convert_bits( data5, &data5_sz, 5, raw, raw_sz, 8, 1 );
  if( rc != AT_BECH32_OK ) return -1;

  char const * hrp = address->mainnet ? AT_BECH32_TOS_MAINNET : AT_BECH32_TOS_TESTNET;
  rc = at_bech32_encode( out, out_sz, hrp, data5, data5_sz );
  return rc >= 0 ? 0 : -1;
}

int
at_address_is_normal( at_address_t const * address ) {
  if( !address ) return 0;
  return address->addr_type == AT_ADDRESS_TYPE_NORMAL;
}

int
at_address_is_mainnet( at_address_t const * address ) {
  if( !address ) return 0;
  return address->mainnet ? 1 : 0;
}

int
at_address_get_public_key( at_address_t const * address,
                           uchar                out[32] ) {
  if( !address || !out ) return -1;
  at_memcpy( out, address->public_key, 32UL );
  return 0;
}

int
at_address_to_public_key( at_address_t * address,
                          uchar          out[32] ) {
  if( !address || !out ) return -1;
  at_memcpy( out, address->public_key, 32UL );
  return 0;
}

int
at_address_get_type( at_address_t const * address,
                     at_address_type_t *  out_type ) {
  if( !address || !out_type ) return -1;
  *out_type = address->addr_type;
  return 0;
}

int
at_address_split( at_address_t *      address,
                  uchar               out_public_key[32],
                  at_address_type_t * out_type,
                  void *              out_data,
                  ulong *             out_data_sz ) {
  if( !address ) return -1;
  if( at_address_get_public_key( address, out_public_key ) != 0 ) return -1;
  if( out_type ) *out_type = address->addr_type;
  return at_address_extract_data_only( address, out_data, out_data_sz, NULL );
}

int
at_address_get_extra_data( at_address_t const * address,
                           void *               out,
                           ulong *              out_sz,
                           int *                has_data_out ) {
  if( has_data_out ) *has_data_out = 0;
  if( !address || !out_sz ) return -1;
  if( address->addr_type != AT_ADDRESS_TYPE_DATA ) return 0;

  ulong cap = *out_sz;
  if( has_data_out ) *has_data_out = 1;
  if( cap < address->integrated_data_sz ) {
    *out_sz = address->integrated_data_sz;
    return -1;
  }
  if( out && address->integrated_data_sz ) {
    at_memcpy( out, address->integrated_data, address->integrated_data_sz );
  }
  *out_sz = address->integrated_data_sz;
  return 0;
}

int
at_address_extract_data_only( at_address_t * address,
                              void *         out,
                              ulong *        out_sz,
                              int *          had_data_out ) {
  if( had_data_out ) *had_data_out = 0;
  if( !address || !out_sz ) return -1;

  if( address->addr_type != AT_ADDRESS_TYPE_DATA ) {
    address->integrated_data_sz = 0UL;
    *out_sz = 0UL;
    return 0;
  }

  ulong cap = *out_sz;
  if( had_data_out ) *had_data_out = 1;
  if( cap < address->integrated_data_sz ) {
    *out_sz = address->integrated_data_sz;
    return -1;
  }

  if( out && address->integrated_data_sz ) {
    at_memcpy( out, address->integrated_data, address->integrated_data_sz );
  }
  *out_sz = address->integrated_data_sz;
  address->integrated_data_sz = 0UL;
  address->addr_type = AT_ADDRESS_TYPE_NORMAL;
  return 0;
}

int
at_address_extract_data( at_address_t const * address,
                         void *               out_data,
                         ulong *              out_data_sz,
                         int *                has_data_out,
                         at_address_t *       out_without_data ) {
  if( !address || !out_without_data || !out_data_sz ) return -1;
  at_memcpy( out_without_data, address, sizeof(*out_without_data) );
  int rc = at_address_extract_data_only( out_without_data, out_data, out_data_sz, has_data_out );
  return rc;
}
