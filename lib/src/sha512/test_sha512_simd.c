/* SHA512 SIMD Equivalence Tests
   Tests that SIMD batch implementations produce identical results to reference.
   Test vectors from ~/avatar/src/tck/test_vectors/sha512.yaml */

#include "at/crypto/at_sha512.h"
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
  char const * expected_hex;
} test_vector_t;

/* Test vectors from src/tck/test_vectors/sha512.yaml */
static test_vector_t const test_vectors[] = {
  { "empty_string", "", 0,
    "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" },
  { "abc", "616263", 3,
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
  { "hello_world", "48656c6c6f2c20776f726c6421", 13,
    "c1527cd893c124773d811911970c8fe6e857d6df5dc9226bd8a160614c0cd963a4ddea2b94bb7d36021ef9d865d5cea294a82dd49a0bb269f51f6e7a57f79421" },
  { "111_bytes_a", "616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161", 111,
    "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2" },
  { "112_bytes_a", "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161", 112,
    "c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca" },
  { "128_bytes_a", "6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161", 128,
    "b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321" },
  { "nist_vector", "61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f696a6b6c6d6e6f706a6b6c6d6e6f70716b6c6d6e6f7071726c6d6e6f707172736d6e6f70717273746e6f707172737475", 112,
    "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909" },
  { "ed25519_seed", "0101010101010101010101010101010101010101010101010101010101010101", 32,
    "5ce86efb75fa4e2c410f46e16de9f6acae1a1703528651b69bc176c088bef3eeb17a2a2cf3d4a41a8e4e18cc45c8656d558eceddb0adb46bfa088a5f53bed252" },
};

#define TEST_VECTOR_CNT (sizeof(test_vectors)/sizeof(test_vectors[0]))

/* Test single reference hash matches expected */
static int
test_reference( test_vector_t const * tv ) {
  uchar input[256];
  uchar expected[64];
  uchar hash[64];

  int input_sz = hex_to_bytes( tv->input_hex, input, sizeof(input) );
  if( input_sz < 0 ) input_sz = 0;
  hex_to_bytes( tv->expected_hex, expected, 64 );

  at_sha512_hash( input, (ulong)input_sz, hash );

  if( at_memcmp( hash, expected, 64 ) != 0 ) {
    printf( "FAIL: reference_%s\n", tv->name );
    printf( "  Expected: %s\n", tv->expected_hex );
    printf( "  Got:      " );
    print_hex( hash, 64 );
    printf( "\n" );
    return 1;
  }

  printf( "PASS: reference_%s\n", tv->name );
  return 0;
}

/* Test batch hash matches reference hash using batch API */
static int
test_batch_vs_reference( void ) {
  int fail = 0;

  /* Prepare batch inputs */
  uchar inputs[TEST_VECTOR_CNT][256];
  uchar ref_hashes[TEST_VECTOR_CNT][64];
  uchar batch_hashes[TEST_VECTOR_CNT][64];

  /* Compute reference hashes */
  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    int sz = hex_to_bytes( test_vectors[i].input_hex, inputs[i], sizeof(inputs[i]) );
    ulong input_sz = (sz < 0) ? 0 : (ulong)sz;
    at_sha512_hash( inputs[i], input_sz, ref_hashes[i] );
  }

  /* Compute batch hashes using batch API */
  at_sha512_batch_t batch_mem[1];
  at_sha512_batch_t * batch = at_sha512_batch_init( batch_mem );

  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    int sz = hex_to_bytes( test_vectors[i].input_hex, inputs[i], sizeof(inputs[i]) );
    ulong input_sz = (sz < 0) ? 0 : (ulong)sz;
    batch = at_sha512_batch_add( batch, inputs[i], input_sz, batch_hashes[i] );
  }

  at_sha512_batch_fini( batch );

  /* Compare batch results with reference */
  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    if( at_memcmp( batch_hashes[i], ref_hashes[i], 64 ) != 0 ) {
      printf( "FAIL: batch_vs_ref_%s\n", test_vectors[i].name );
      printf( "  Reference: " );
      print_hex( ref_hashes[i], 64 );
      printf( "\n  Batch:     " );
      print_hex( batch_hashes[i], 64 );
      printf( "\n" );
      fail++;
    } else {
      printf( "PASS: batch_vs_ref_%s\n", test_vectors[i].name );
    }
  }

  return fail;
}

/* Test batch with different batch sizes (1 to 4) */
static int
test_batch_sizes( void ) {
  int fail = 0;

  uchar input[128];
  at_memset( input, 0x42, 128 );

  for( ulong batch_cnt = 1; batch_cnt <= 4; batch_cnt++ ) {
    uchar ref_hash[64];
    uchar batch_hashes[4][64];

    /* Compute reference hash */
    at_sha512_hash( input, 128, ref_hash );

    /* Run batch */
    at_sha512_batch_t batch_mem[1];
    at_sha512_batch_t * batch = at_sha512_batch_init( batch_mem );

    for( ulong i = 0; i < batch_cnt; i++ ) {
      batch = at_sha512_batch_add( batch, input, 128, batch_hashes[i] );
    }

    at_sha512_batch_fini( batch );

    /* Verify all match reference */
    int batch_ok = 1;
    for( ulong i = 0; i < batch_cnt; i++ ) {
      if( at_memcmp( batch_hashes[i], ref_hash, 64 ) != 0 ) {
        batch_ok = 0;
        break;
      }
    }

    if( !batch_ok ) {
      printf( "FAIL: batch_size_%lu\n", batch_cnt );
      fail++;
    } else {
      printf( "PASS: batch_size_%lu\n", batch_cnt );
    }
  }

  return fail;
}

/* Test batch with mixed message sizes */
static int
test_batch_mixed_sizes( void ) {
  int fail = 0;

  uchar inputs[4][256];
  ulong sizes[] = { 0, 32, 111, 128 };
  uchar ref_hashes[4][64];
  uchar batch_hashes[4][64];

  for( ulong i = 0; i < 4; i++ ) {
    at_memset( inputs[i], (uchar)(0x30 + i), sizes[i] );
    at_sha512_hash( inputs[i], sizes[i], ref_hashes[i] );
  }

  at_sha512_batch_t batch_mem[1];
  at_sha512_batch_t * batch = at_sha512_batch_init( batch_mem );

  for( ulong i = 0; i < 4; i++ ) {
    batch = at_sha512_batch_add( batch, inputs[i], sizes[i], batch_hashes[i] );
  }

  at_sha512_batch_fini( batch );

  int all_match = 1;
  for( ulong i = 0; i < 4; i++ ) {
    if( at_memcmp( batch_hashes[i], ref_hashes[i], 64 ) != 0 ) {
      all_match = 0;
      printf( "FAIL: batch_mixed_size_%lu (size=%lu)\n", i, sizes[i] );
      fail++;
    }
  }

  if( all_match ) {
    printf( "PASS: batch_mixed_sizes (all 4 sizes match)\n" );
  }

  return fail;
}

int main( void ) {
  int fail = 0;

  printf( "=== SHA512 Reference Tests ===\n" );
  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    fail += test_reference( &test_vectors[i] );
  }

  printf( "\n=== SHA512 Batch vs Reference Tests ===\n" );
  fail += test_batch_vs_reference();

  printf( "\n=== SHA512 Batch Size Tests ===\n" );
  fail += test_batch_sizes();

  printf( "\n=== SHA512 Mixed Size Batch Test ===\n" );
  fail += test_batch_mixed_sizes();

  printf( "\n%d total tests, %d failures\n",
          (int)(TEST_VECTOR_CNT + TEST_VECTOR_CNT + 4 + 1), fail );
  printf( "%s\n", fail ? "SOME TESTS FAILED" : "ALL TESTS PASSED" );

  return fail;
}
