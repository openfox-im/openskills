/* SHA3 SIMD Equivalence Tests
   Tests that SIMD batch implementations produce identical results to reference.
   Test vectors from ~/avatar/src/tck/test_vectors/sha3_512.yaml */

#include "at/crypto/at_sha3.h"
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

/* SHA3-512 test vector structure */
typedef struct {
  char const * name;
  char const * input_hex;
  ulong        input_length;
  char const * expected_hex;
} test_vector_512_t;

/* SHA3-256 test vector structure */
typedef struct {
  char const * name;
  char const * input_hex;
  ulong        input_length;
  char const * expected_hex;
} test_vector_256_t;

/* SHA3-512 test vectors from src/tck/test_vectors/sha3_512.yaml */
static test_vector_512_t const test_vectors_512[] = {
  { "empty_string", "", 0,
    "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26" },
  { "abc", "616263", 3,
    "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0" },
  { "hello_world", "48656c6c6f2c20776f726c6421", 13,
    "8e47f1185ffd014d238fabd02a1a32defe698cbf38c037a90e3c0a0a32370fb52cbd641250508502295fcabcbf676c09470b27443868c8e5f70e26dc337288af" },
  { "71_bytes_a", "6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161", 71,
    "070faf98d2a8fddf8ed886408744dc06456096c2e045f26f3c7b010530e6bbb3db535a54d636856f4e0e1e982461cb9a7e8e57ff8895cff1619af9f0e486e28c" },
  { "72_bytes_a", "616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161", 72,
    "a8ae722a78e10cbbc413886c02eb5b369a03f6560084aff566bd597bb7ad8c1ccd86e81296852359bf2faddb5153c0a7445722987875e74287adac21adebe952" },
};

#define TEST_VECTOR_512_CNT (sizeof(test_vectors_512)/sizeof(test_vectors_512[0]))

/* Test reference SHA3-512 hash matches expected */
static int
test_sha3_512_reference( test_vector_512_t const * tv ) {
  uchar input[256];
  uchar expected[64];
  uchar hash[64];

  int input_sz = hex_to_bytes( tv->input_hex, input, sizeof(input) );
  if( input_sz < 0 ) input_sz = 0;
  hex_to_bytes( tv->expected_hex, expected, 64 );

  at_sha3_512_hash( input, (ulong)input_sz, hash );

  if( at_memcmp( hash, expected, 64 ) != 0 ) {
    printf( "FAIL: sha3_512_reference_%s\n", tv->name );
    printf( "  Expected: %s\n", tv->expected_hex );
    printf( "  Got:      " );
    print_hex( hash, 64 );
    printf( "\n" );
    return 1;
  }

  printf( "PASS: sha3_512_reference_%s\n", tv->name );
  return 0;
}

/* Test batch SHA3-512 hash matches reference */
static int
test_sha3_512_batch_vs_reference( void ) {
  int fail = 0;

  /* Prepare inputs */
  uchar inputs[TEST_VECTOR_512_CNT][256];
  uchar ref_hashes[TEST_VECTOR_512_CNT][64];
  uchar batch_hashes[TEST_VECTOR_512_CNT][64];

  /* Compute reference hashes */
  for( ulong i = 0; i < TEST_VECTOR_512_CNT; i++ ) {
    int sz = hex_to_bytes( test_vectors_512[i].input_hex, inputs[i], sizeof(inputs[i]) );
    ulong input_sz = (sz < 0) ? 0 : (ulong)sz;
    at_sha3_512_hash( inputs[i], input_sz, ref_hashes[i] );
  }

  /* Compute batch hashes */
  uchar batch_mem[ AT_SHA3_512_BATCH_FOOTPRINT ] __attribute__((aligned(AT_SHA3_512_BATCH_ALIGN)));
  at_sha3_512_batch_t * batch = at_sha3_512_batch_init( batch_mem );

  for( ulong i = 0; i < TEST_VECTOR_512_CNT; i++ ) {
    int sz = hex_to_bytes( test_vectors_512[i].input_hex, inputs[i], sizeof(inputs[i]) );
    ulong input_sz = (sz < 0) ? 0 : (ulong)sz;
    batch = at_sha3_512_batch_add( batch, inputs[i], input_sz, batch_hashes[i] );
  }

  at_sha3_512_batch_fini( batch );

  /* Compare */
  for( ulong i = 0; i < TEST_VECTOR_512_CNT; i++ ) {
    if( at_memcmp( batch_hashes[i], ref_hashes[i], 64 ) != 0 ) {
      printf( "FAIL: sha3_512_batch_vs_ref_%s\n", test_vectors_512[i].name );
      printf( "  Reference: " );
      print_hex( ref_hashes[i], 64 );
      printf( "\n  Batch:     " );
      print_hex( batch_hashes[i], 64 );
      printf( "\n" );
      fail++;
    } else {
      printf( "PASS: sha3_512_batch_vs_ref_%s\n", test_vectors_512[i].name );
    }
  }

  return fail;
}

/* Test batch with varying batch sizes */
static int
test_sha3_512_batch_sizes( void ) {
  int fail = 0;

  uchar input[64];
  at_memset( input, 0x42, 64 );

  uchar ref_hash[64];
  at_sha3_512_hash( input, 64, ref_hash );

  for( ulong batch_cnt = 1; batch_cnt <= AT_SHA3_512_BATCH_MAX; batch_cnt++ ) {
    uchar batch_hashes[AT_SHA3_512_BATCH_MAX][64];

    uchar batch_mem[ AT_SHA3_512_BATCH_FOOTPRINT ] __attribute__((aligned(AT_SHA3_512_BATCH_ALIGN)));
    at_sha3_512_batch_t * batch = at_sha3_512_batch_init( batch_mem );

    for( ulong i = 0; i < batch_cnt; i++ ) {
      batch = at_sha3_512_batch_add( batch, input, 64, batch_hashes[i] );
    }

    at_sha3_512_batch_fini( batch );

    int batch_ok = 1;
    for( ulong i = 0; i < batch_cnt; i++ ) {
      if( at_memcmp( batch_hashes[i], ref_hash, 64 ) != 0 ) {
        batch_ok = 0;
        break;
      }
    }

    if( !batch_ok ) {
      printf( "FAIL: sha3_512_batch_size_%lu\n", batch_cnt );
      fail++;
    } else {
      printf( "PASS: sha3_512_batch_size_%lu\n", batch_cnt );
    }
  }

  return fail;
}

/* Test batch with mixed message sizes */
static int
test_sha3_512_batch_mixed_sizes( void ) {
  int fail = 0;

  uchar inputs[AT_SHA3_512_BATCH_MAX][256];
  ulong sizes[AT_SHA3_512_BATCH_MAX];
  uchar ref_hashes[AT_SHA3_512_BATCH_MAX][64];
  uchar batch_hashes[AT_SHA3_512_BATCH_MAX][64];

  /* Use different sizes up to batch max */
  ulong test_sizes[] = { 0, 1, 32, 71, 72, 100, 128, 200 };
  ulong num_tests = AT_SHA3_512_BATCH_MAX;
  if( num_tests > sizeof(test_sizes)/sizeof(test_sizes[0]) ) {
    num_tests = sizeof(test_sizes)/sizeof(test_sizes[0]);
  }

  for( ulong i = 0; i < num_tests; i++ ) {
    sizes[i] = test_sizes[i];
    at_memset( inputs[i], (uchar)(0x30 + i), sizes[i] );
    at_sha3_512_hash( inputs[i], sizes[i], ref_hashes[i] );
  }

  uchar batch_mem[ AT_SHA3_512_BATCH_FOOTPRINT ] __attribute__((aligned(AT_SHA3_512_BATCH_ALIGN)));
  at_sha3_512_batch_t * batch = at_sha3_512_batch_init( batch_mem );

  for( ulong i = 0; i < num_tests; i++ ) {
    batch = at_sha3_512_batch_add( batch, inputs[i], sizes[i], batch_hashes[i] );
  }

  at_sha3_512_batch_fini( batch );

  int all_match = 1;
  for( ulong i = 0; i < num_tests; i++ ) {
    if( at_memcmp( batch_hashes[i], ref_hashes[i], 64 ) != 0 ) {
      all_match = 0;
      printf( "FAIL: sha3_512_batch_mixed_size_%lu (size=%lu)\n", i, sizes[i] );
      fail++;
    }
  }

  if( all_match ) {
    printf( "PASS: sha3_512_batch_mixed_sizes (all %lu sizes match)\n", num_tests );
  }

  return fail;
}

/* Test SHA3-256 batch */
static int
test_sha3_256_batch( void ) {
  int fail = 0;

  uchar input[64];
  at_memset( input, 0x42, 64 );

  uchar ref_hash[32];
  at_sha3_256_hash( input, 64, ref_hash );

  for( ulong batch_cnt = 1; batch_cnt <= AT_SHA3_256_BATCH_MAX; batch_cnt++ ) {
    uchar batch_hashes[AT_SHA3_256_BATCH_MAX][32];

    uchar batch_mem[ AT_SHA3_256_BATCH_FOOTPRINT ] __attribute__((aligned(AT_SHA3_256_BATCH_ALIGN)));
    at_sha3_256_batch_t * batch = at_sha3_256_batch_init( batch_mem );

    for( ulong i = 0; i < batch_cnt; i++ ) {
      batch = at_sha3_256_batch_add( batch, input, 64, batch_hashes[i] );
    }

    at_sha3_256_batch_fini( batch );

    int batch_ok = 1;
    for( ulong i = 0; i < batch_cnt; i++ ) {
      if( at_memcmp( batch_hashes[i], ref_hash, 32 ) != 0 ) {
        batch_ok = 0;
        break;
      }
    }

    if( !batch_ok ) {
      printf( "FAIL: sha3_256_batch_size_%lu\n", batch_cnt );
      fail++;
    } else {
      printf( "PASS: sha3_256_batch_size_%lu\n", batch_cnt );
    }
  }

  return fail;
}

/* Test consistency: multiple batch calls produce same result */
static int
test_sha3_512_consistency( void ) {
  int fail = 0;

  uchar input[128];
  at_memset( input, 0xAB, 128 );

  uchar hash1[64], hash2[64];

  /* First batch */
  uchar batch_mem1[ AT_SHA3_512_BATCH_FOOTPRINT ] __attribute__((aligned(AT_SHA3_512_BATCH_ALIGN)));
  at_sha3_512_batch_t * batch1 = at_sha3_512_batch_init( batch_mem1 );
  batch1 = at_sha3_512_batch_add( batch1, input, 128, hash1 );
  at_sha3_512_batch_fini( batch1 );

  /* Second batch */
  uchar batch_mem2[ AT_SHA3_512_BATCH_FOOTPRINT ] __attribute__((aligned(AT_SHA3_512_BATCH_ALIGN)));
  at_sha3_512_batch_t * batch2 = at_sha3_512_batch_init( batch_mem2 );
  batch2 = at_sha3_512_batch_add( batch2, input, 128, hash2 );
  at_sha3_512_batch_fini( batch2 );

  if( at_memcmp( hash1, hash2, 64 ) != 0 ) {
    printf( "FAIL: sha3_512_consistency\n" );
    fail++;
  } else {
    printf( "PASS: sha3_512_consistency\n" );
  }

  return fail;
}

int main( void ) {
  int fail = 0;

  printf( "=== SHA3-512 Reference Tests ===\n" );
  for( ulong i = 0; i < TEST_VECTOR_512_CNT; i++ ) {
    fail += test_sha3_512_reference( &test_vectors_512[i] );
  }

  printf( "\n=== SHA3-512 Batch vs Reference Tests ===\n" );
  fail += test_sha3_512_batch_vs_reference();

  printf( "\n=== SHA3-512 Batch Size Tests ===\n" );
  fail += test_sha3_512_batch_sizes();

  printf( "\n=== SHA3-512 Mixed Size Batch Test ===\n" );
  fail += test_sha3_512_batch_mixed_sizes();

  printf( "\n=== SHA3-256 Batch Tests ===\n" );
  fail += test_sha3_256_batch();

  printf( "\n=== SHA3-512 Consistency Tests ===\n" );
  fail += test_sha3_512_consistency();

  printf( "\n%d total failures\n", fail );
  printf( "%s\n", fail ? "SOME TESTS FAILED" : "ALL TESTS PASSED" );

  return fail;
}
