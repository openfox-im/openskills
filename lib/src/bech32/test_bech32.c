/* Bech32 encoding tests using test vectors from TOS TCK
   Test vectors loaded from ~/tos/tck/crypto/bech32.yaml
   Supports both YAML-based and hardcoded tests */

#include <at/crypto/at_bech32.h>
#include <at/infra/at_yaml.h>
#include <stdio.h>
#include <string.h>

static void
print_hex( uchar const * data, ulong sz ) {
  for( ulong i = 0; i < sz; i++ ) {
    printf( "%02x", data[ i ] );
  }
}

/* Test convert_bits function */
static int
test_convert_bits( void ) {
  int fail = 0;

  /* Test 8->5 conversion */
  {
    uchar in[] = { 0x00, 0x14, 0x75, 0x1e };
    uchar expected[] = { 0x00, 0x00, 0x0a, 0x07, 0x0a, 0x07, 0x10 };
    uchar out[ 16 ];
    ulong out_sz = sizeof( out );

    int ret = at_bech32_convert_bits( out, &out_sz, 5, in, sizeof( in ), 8, 1 );
    if( ret != AT_BECH32_OK ) {
      printf( "FAIL: convert_bits_8to5 (ret=%d)\n", ret );
      fail++;
    } else if( out_sz != sizeof( expected ) || at_memcmp( out, expected, out_sz ) != 0 ) {
      printf( "FAIL: convert_bits_8to5 (data mismatch)\n" );
      printf( "  Expected: " ); print_hex( expected, sizeof( expected ) ); printf( "\n" );
      printf( "  Got:      " ); print_hex( out, out_sz ); printf( "\n" );
      fail++;
    } else {
      printf( "PASS: convert_bits_8to5\n" );
    }
  }

  /* Test 5->8 conversion (reverse) */
  {
    uchar in[] = { 0x00, 0x00, 0x0a, 0x07, 0x0a, 0x07, 0x10 };
    uchar expected[] = { 0x00, 0x14, 0x75, 0x1e };
    uchar out[ 16 ];
    ulong out_sz = sizeof( out );

    int ret = at_bech32_convert_bits( out, &out_sz, 8, in, sizeof( in ), 5, 0 );
    if( ret != AT_BECH32_OK ) {
      printf( "FAIL: convert_bits_5to8 (ret=%d)\n", ret );
      fail++;
    } else if( out_sz != sizeof( expected ) || at_memcmp( out, expected, out_sz ) != 0 ) {
      printf( "FAIL: convert_bits_5to8 (data mismatch)\n" );
      printf( "  Expected: " ); print_hex( expected, sizeof( expected ) ); printf( "\n" );
      printf( "  Got:      " ); print_hex( out, out_sz ); printf( "\n" );
      fail++;
    } else {
      printf( "PASS: convert_bits_5to8\n" );
    }
  }

  return fail;
}

/* Test basic Bech32 encoding */
static int
test_bech32_encode( char const * name,
                    char const * hrp,
                    char const * data_5bit_hex,
                    char const * expected_encoded ) {
  uchar data[ 64 ];
  int data_sz = at_yaml_hex_to_bytes( data, sizeof( data ), data_5bit_hex );
  if( data_sz < 0 ) data_sz = 0;

  char out[ 128 ];
  int ret = at_bech32_encode( out, sizeof( out ), hrp, data, (ulong)data_sz );

  if( ret < 0 ) {
    printf( "FAIL: %s_encode (ret=%d)\n", name, ret );
    return 1;
  }

  if( at_strcmp( out, expected_encoded ) != 0 ) {
    printf( "FAIL: %s_encode\n", name );
    printf( "  Expected: %s\n", expected_encoded );
    printf( "  Got:      %s\n", out );
    return 1;
  }

  printf( "PASS: %s_encode\n", name );
  return 0;
}

/* Test Bech32 decoding */
static int
test_bech32_decode( char const * name,
                    char const * encoded,
                    char const * expected_hrp,
                    char const * expected_data_5bit_hex ) {
  char hrp[ 16 ];
  uchar data[ 64 ];
  ulong data_sz = sizeof( data );

  int ret = at_bech32_decode( encoded, hrp, sizeof( hrp ), data, &data_sz );

  if( ret != AT_BECH32_OK ) {
    printf( "FAIL: %s_decode (ret=%d)\n", name, ret );
    return 1;
  }

  if( at_strcmp( hrp, expected_hrp ) != 0 ) {
    printf( "FAIL: %s_decode (hrp mismatch)\n", name );
    printf( "  Expected: %s\n", expected_hrp );
    printf( "  Got:      %s\n", hrp );
    return 1;
  }

  uchar expected_data[ 64 ];
  int expected_sz = at_yaml_hex_to_bytes( expected_data, sizeof( expected_data ), expected_data_5bit_hex );
  if( expected_sz < 0 ) expected_sz = 0;

  if( data_sz != (ulong)expected_sz || at_memcmp( data, expected_data, data_sz ) != 0 ) {
    printf( "FAIL: %s_decode (data mismatch)\n", name );
    printf( "  Expected: %s\n", expected_data_5bit_hex );
    printf( "  Got:      " ); print_hex( data, data_sz ); printf( "\n" );
    return 1;
  }

  printf( "PASS: %s_decode\n", name );
  return 0;
}

/* Test TOS address encoding */
static int
test_address_encode( char const * name,
                     int          mainnet,
                     char const * public_key_hex,
                     char const * expected_address ) {
  uchar public_key[ 32 ];
  at_yaml_hex_to_bytes( public_key, 32, public_key_hex );

  char out[ 128 ];
  int ret = at_bech32_address_encode( out, sizeof( out ), mainnet, public_key );

  if( ret < 0 ) {
    printf( "FAIL: %s_encode (ret=%d)\n", name, ret );
    return 1;
  }

  if( at_strcmp( out, expected_address ) != 0 ) {
    printf( "FAIL: %s_encode\n", name );
    printf( "  Expected: %s\n", expected_address );
    printf( "  Got:      %s\n", out );
    return 1;
  }

  printf( "PASS: %s_encode\n", name );
  return 0;
}

/* Test TOS address decoding */
static int
test_address_decode( char const * name,
                     char const * address,
                     int          expected_mainnet,
                     char const * expected_public_key_hex ) {
  int mainnet = -1;
  uchar public_key[ 32 ];

  int ret = at_bech32_address_decode( address, &mainnet, public_key );

  if( ret != AT_BECH32_OK ) {
    printf( "FAIL: %s_decode (ret=%d)\n", name, ret );
    return 1;
  }

  if( mainnet != expected_mainnet ) {
    printf( "FAIL: %s_decode (mainnet mismatch)\n", name );
    printf( "  Expected: %d\n", expected_mainnet );
    printf( "  Got:      %d\n", mainnet );
    return 1;
  }

  uchar expected_key[ 32 ];
  at_yaml_hex_to_bytes( expected_key, 32, expected_public_key_hex );

  if( at_memcmp( public_key, expected_key, 32 ) != 0 ) {
    printf( "FAIL: %s_decode (public_key mismatch)\n", name );
    printf( "  Expected: %s\n", expected_public_key_hex );
    printf( "  Got:      " ); print_hex( public_key, 32 ); printf( "\n" );
    return 1;
  }

  printf( "PASS: %s_decode\n", name );
  return 0;
}

/* Test checksum verification */
static int
test_checksum_verification( void ) {
  int fail = 0;

  /* Valid addresses */
  if( !at_bech32_verify_checksum( "tos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhcaa6f" ) ) {
    printf( "FAIL: valid_checksum_1\n" );
    fail++;
  } else {
    printf( "PASS: valid_checksum_1\n" );
  }

  /* Invalid checksum (last char modified) */
  if( at_bech32_verify_checksum( "tos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhcaa6g" ) ) {
    printf( "FAIL: invalid_checksum_1 (should have failed)\n" );
    fail++;
  } else {
    printf( "PASS: invalid_checksum_1\n" );
  }

  return fail;
}

/* Run tests from YAML file */
static int
test_from_yaml( char const * yaml_path ) {
  int fail = 0;
  at_yaml_doc_t doc;

  printf( "Loading test vectors from: %s\n\n", yaml_path );

  if( at_yaml_parse_file( &doc, yaml_path ) != 0 ) {
    printf( "FAIL: Failed to parse YAML file\n" );
    return 1;
  }

  /* Verify algorithm */
  char const * algo = at_yaml_get_string( &doc, "algorithm" );
  if( !algo || at_strcmp( algo, "Bech32" ) != 0 ) {
    printf( "FAIL: Expected algorithm 'Bech32', got '%s'\n", algo ? algo : "(null)" );
    return 1;
  }

  /* Test bech32_vectors */
  at_yaml_array_t const * bech32_vectors = at_yaml_get_array( &doc, "bech32_vectors" );
  if( bech32_vectors ) {
    printf( "=== Bech32 Encode/Decode Tests (from YAML) ===\n" );
    for( int i = 0; i < bech32_vectors->item_count; i++ ) {
      at_yaml_obj_t const * v = &bech32_vectors->items[ i ];
      char const * name = at_yaml_obj_get_string( v, "name" );
      char const * hrp = at_yaml_obj_get_string( v, "hrp" );
      char const * data_5bit_hex = at_yaml_obj_get_string( v, "data_5bit_hex" );
      char const * encoded = at_yaml_obj_get_string( v, "encoded" );

      if( name && hrp && data_5bit_hex && encoded ) {
        fail += test_bech32_encode( name, hrp, data_5bit_hex, encoded );
        fail += test_bech32_decode( name, encoded, hrp, data_5bit_hex );
      }
    }
  }

  /* Test address_vectors */
  at_yaml_array_t const * address_vectors = at_yaml_get_array( &doc, "address_vectors" );
  if( address_vectors ) {
    printf( "\n=== TOS Address Tests (from YAML) ===\n" );
    for( int i = 0; i < address_vectors->item_count; i++ ) {
      at_yaml_obj_t const * v = &address_vectors->items[ i ];
      char const * name = at_yaml_obj_get_string( v, "name" );
      int mainnet = at_yaml_obj_get_bool( v, "mainnet" );
      char const * public_key_hex = at_yaml_obj_get_string( v, "public_key_hex" );
      char const * address = at_yaml_obj_get_string( v, "address" );

      if( name && public_key_hex && address ) {
        fail += test_address_encode( name, mainnet, public_key_hex, address );
        fail += test_address_decode( name, address, mainnet, public_key_hex );
      }
    }
  }

  return fail;
}

int main( int argc, char ** argv ) {
  int fail = 0;

  printf( "=== Convert Bits Tests ===\n" );
  fail += test_convert_bits();

  if( argc > 1 ) {
    /* YAML-based testing */
    printf( "\n" );
    fail += test_from_yaml( argv[ 1 ] );
  } else {
    /* Hardcoded test vectors (fallback) */
    printf( "\n=== Bech32 Encode/Decode Tests ===\n" );

    /* simple_tos */
    fail += test_bech32_encode( "simple_tos", "tos", "00000a070a0710", "tos1qq2828s7x3ce7" );
    fail += test_bech32_decode( "simple_tos", "tos1qq2828s7x3ce7", "tos", "00000a070a0710" );

    /* simple_tst */
    fail += test_bech32_encode( "simple_tst", "tst", "150f061e1e0410", "tst140x77ysn66he5" );
    fail += test_bech32_decode( "simple_tst", "tst140x77ysn66he5", "tst", "150f061e1e0410" );

    printf( "\n=== TOS Address Tests ===\n" );

    /* zeros_mainnet */
    fail += test_address_encode( "zeros_mainnet", 1,
      "0000000000000000000000000000000000000000000000000000000000000000",
      "tos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhcaa6f" );
    fail += test_address_decode( "zeros_mainnet",
      "tos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhcaa6f", 1,
      "0000000000000000000000000000000000000000000000000000000000000000" );

    /* zeros_testnet */
    fail += test_address_encode( "zeros_testnet", 0,
      "0000000000000000000000000000000000000000000000000000000000000000",
      "tst1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqvg5uj9" );
    fail += test_address_decode( "zeros_testnet",
      "tst1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqvg5uj9", 0,
      "0000000000000000000000000000000000000000000000000000000000000000" );

    /* sequential_mainnet */
    fail += test_address_encode( "sequential_mainnet", 1,
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "tos1qqqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50p7knpe4h" );
    fail += test_address_decode( "sequential_mainnet",
      "tos1qqqqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50p7knpe4h", 1,
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" );

    /* all_ff_testnet */
    fail += test_address_encode( "all_ff_testnet", 0,
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "tst1qrllllllllllllllllllllllllllllllllllllllllllllllllll7czqtsx" );
    fail += test_address_decode( "all_ff_testnet",
      "tst1qrllllllllllllllllllllllllllllllllllllllllllllllllll7czqtsx", 0,
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" );

    /* schnorr_pubkey_mainnet */
    fail += test_address_encode( "schnorr_pubkey_mainnet", 1,
      "3cc4fec02e2342dca15352d5c5c27135f9e42c5805c07ca9dc500e000f89a665",
      "tos1qq7vflkq9c359h9p2dfdt3wzwy6lnepvtqzuql9fm3gquqq03xnx28jpnkv" );
    fail += test_address_decode( "schnorr_pubkey_mainnet",
      "tos1qq7vflkq9c359h9p2dfdt3wzwy6lnepvtqzuql9fm3gquqq03xnx28jpnkv", 1,
      "3cc4fec02e2342dca15352d5c5c27135f9e42c5805c07ca9dc500e000f89a665" );
  }

  printf( "\n=== Checksum Verification Tests ===\n" );
  fail += test_checksum_verification();

  printf( "\n%d failures\n", fail );
  printf( "%s\n", fail ? "SOME TESTS FAILED" : "ALL TESTS PASSED" );
  return fail;
}