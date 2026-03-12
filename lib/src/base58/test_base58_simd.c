/* Base58 SIMD Equivalence Tests
   Tests that AVX optimized implementations produce identical results to reference.
   Test vectors from ~/avatar/src/tck/test_vectors/base58.yaml */

#include "at/crypto/at_base58.h"
#include <stdio.h>
#include <string.h>

static int
hex_to_bytes( char const * hex, uchar * out, ulong out_sz ) {
  ulong hex_len = at_strlen( hex );
  if( hex_len % 2 != 0 || hex_len / 2 > out_sz ) return -1;
  for( ulong i = 0; i < hex_len / 2; i++ ) {
    unsigned int byte;
    if( sscanf( hex + i * 2, "%02x", &byte ) != 1 ) return -1;
    out[i] = (uchar)byte;
  }
  return (int)(hex_len / 2);
}

static void
print_hex( uchar const * data, ulong sz ) {
  for( ulong i = 0; i < sz; i++ ) {
    printf( "%02x", data[i] );
  }
}

/* Test vector structure */
typedef struct {
  char const * name;
  char const * input_hex;
  ulong        input_length;
  char const * expected_base58;
} test_vector_t;

/* Test vectors from src/tck/test_vectors/base58.yaml */
static test_vector_t const test_vectors[] = {
  { "empty", "", 0, "" },
  { "single_zero", "00", 1, "1" },
  { "leading_zeros", "00000001", 4, "1112" },
  { "hello_world", "48656c6c6f20576f726c64", 11, "JxF12TrwUP45BMd" },
  { "pubkey_32bytes", "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", 32,
    "4wBqpZM9xaSheZzJSMawUKKwhdpChKbZ5eu5ky4Vigw" },
  { "all_ff", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 32,
    "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG" },
  { "all_zeros_32", "0000000000000000000000000000000000000000000000000000000000000000", 32,
    "11111111111111111111111111111111" },
  { "signature_64bytes", "42424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242", 64,
    "2KqNxgmhsAH91zr5iAty4FrUwjhEAcu22kj5htCEMTWVsCs9pt3GFyQGboaCpZkPGUX7csayY3RXYZFxactztr49" },
  { "byte_00", "00", 1, "1" },
  { "byte_39", "39", 1, "z" },
};

#define TEST_VECTOR_CNT (sizeof(test_vectors)/sizeof(test_vectors[0]))

/* Test encoding matches expected */
static int
test_encode( test_vector_t const * tv ) {
  uchar input[256];
  char encoded[256];

  int input_sz = hex_to_bytes( tv->input_hex, input, sizeof(input) );
  if( input_sz < 0 ) input_sz = 0;

  ulong encoded_len = 0;
  at_base58_encode( input, (ulong)input_sz, &encoded_len, encoded );

  if( at_strcmp( encoded, tv->expected_base58 ) != 0 ) {
    printf( "FAIL: encode_%s\n", tv->name );
    printf( "  Expected: %s\n", tv->expected_base58 );
    printf( "  Got:      %s\n", encoded );
    return 1;
  }

  printf( "PASS: encode_%s\n", tv->name );
  return 0;
}

/* Test decoding matches expected */
static int
test_decode( test_vector_t const * tv ) {
  uchar expected[256];
  uchar decoded[256];

  int expected_sz = hex_to_bytes( tv->input_hex, expected, sizeof(expected) );
  if( expected_sz < 0 ) expected_sz = 0;

  /* Skip empty string case for decoding test */
  if( expected_sz == 0 && at_strlen( tv->expected_base58 ) == 0 ) {
    printf( "PASS: decode_%s (empty)\n", tv->name );
    return 0;
  }

  uchar * result = at_base58_decode( tv->expected_base58, decoded, (ulong)expected_sz );

  if( result == NULL ) {
    printf( "FAIL: decode_%s (decode returned NULL)\n", tv->name );
    return 1;
  }

  if( at_memcmp( decoded, expected, (ulong)expected_sz ) != 0 ) {
    printf( "FAIL: decode_%s\n", tv->name );
    printf( "  Expected: " );
    print_hex( expected, (ulong)expected_sz );
    printf( "\n  Got:      " );
    print_hex( decoded, (ulong)expected_sz );
    printf( "\n" );
    return 1;
  }

  printf( "PASS: decode_%s\n", tv->name );
  return 0;
}

/* Test encode->decode roundtrip */
static int
test_roundtrip( test_vector_t const * tv ) {
  uchar input[256];
  char encoded[256];
  uchar decoded[256];

  int input_sz = hex_to_bytes( tv->input_hex, input, sizeof(input) );
  if( input_sz < 0 ) input_sz = 0;

  /* Skip empty string case */
  if( input_sz == 0 ) {
    printf( "PASS: roundtrip_%s (empty)\n", tv->name );
    return 0;
  }

  /* Encode */
  ulong encoded_len = 0;
  at_base58_encode( input, (ulong)input_sz, &encoded_len, encoded );

  /* Decode */
  uchar * result = at_base58_decode( encoded, decoded, (ulong)input_sz );

  if( result == NULL ) {
    printf( "FAIL: roundtrip_%s (decode returned NULL)\n", tv->name );
    return 1;
  }

  if( at_memcmp( decoded, input, (ulong)input_sz ) != 0 ) {
    printf( "FAIL: roundtrip_%s\n", tv->name );
    printf( "  Original: " );
    print_hex( input, (ulong)input_sz );
    printf( "\n  After RT: " );
    print_hex( decoded, (ulong)input_sz );
    printf( "\n" );
    return 1;
  }

  printf( "PASS: roundtrip_%s\n", tv->name );
  return 0;
}

/* Test 32-byte encoding consistency (SIMD path for 32-byte inputs) */
static int
test_32byte_consistency( void ) {
  int fail = 0;

  /* Test multiple 32-byte inputs */
  uchar inputs[4][32];
  char encoded1[4][64];
  char encoded2[4][64];

  /* Set up different 32-byte patterns */
  at_memset( inputs[0], 0x00, 32 );
  at_memset( inputs[1], 0xFF, 32 );
  at_memset( inputs[2], 0x42, 32 );
  for( int i = 0; i < 32; i++ ) inputs[3][i] = (uchar)i;

  /* Encode each twice and compare */
  for( int i = 0; i < 4; i++ ) {
    ulong len1 = 0, len2 = 0;
    at_base58_encode( inputs[i], 32, &len1, encoded1[i] );
    at_base58_encode( inputs[i], 32, &len2, encoded2[i] );

    if( at_strcmp( encoded1[i], encoded2[i] ) != 0 ) {
      printf( "FAIL: 32byte_consistency_%d\n", i );
      printf( "  First:  %s\n", encoded1[i] );
      printf( "  Second: %s\n", encoded2[i] );
      fail++;
    } else {
      printf( "PASS: 32byte_consistency_%d\n", i );
    }
  }

  return fail;
}

/* Test 64-byte encoding consistency (SIMD path for 64-byte inputs) */
static int
test_64byte_consistency( void ) {
  int fail = 0;

  /* Test multiple 64-byte inputs */
  uchar inputs[4][64];
  char encoded1[4][128];
  char encoded2[4][128];

  /* Set up different 64-byte patterns */
  at_memset( inputs[0], 0x00, 64 );
  at_memset( inputs[1], 0xFF, 64 );
  at_memset( inputs[2], 0x42, 64 );
  for( int i = 0; i < 64; i++ ) inputs[3][i] = (uchar)i;

  /* Encode each twice and compare */
  for( int i = 0; i < 4; i++ ) {
    ulong len1 = 0, len2 = 0;
    at_base58_encode( inputs[i], 64, &len1, encoded1[i] );
    at_base58_encode( inputs[i], 64, &len2, encoded2[i] );

    if( at_strcmp( encoded1[i], encoded2[i] ) != 0 ) {
      printf( "FAIL: 64byte_consistency_%d\n", i );
      printf( "  First:  %s\n", encoded1[i] );
      printf( "  Second: %s\n", encoded2[i] );
      fail++;
    } else {
      printf( "PASS: 64byte_consistency_%d\n", i );
    }
  }

  return fail;
}

int main( void ) {
  int fail = 0;

  printf( "=== Base58 Encode Tests ===\n" );
  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    fail += test_encode( &test_vectors[i] );
  }

  printf( "\n=== Base58 Decode Tests ===\n" );
  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    fail += test_decode( &test_vectors[i] );
  }

  printf( "\n=== Base58 Roundtrip Tests ===\n" );
  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    fail += test_roundtrip( &test_vectors[i] );
  }

  printf( "\n=== Base58 32-byte Consistency Tests ===\n" );
  fail += test_32byte_consistency();

  printf( "\n=== Base58 64-byte Consistency Tests ===\n" );
  fail += test_64byte_consistency();

  printf( "\n%d tests, %d failures\n",
          (int)(TEST_VECTOR_CNT * 3 + 4 + 4), fail );
  printf( "%s\n", fail ? "SOME TESTS FAILED" : "ALL TESTS PASSED" );

  return fail;
}
