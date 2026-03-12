/* Keccak256 SIMD Equivalence Tests
   Tests that SIMD batch implementations produce identical results to reference.
   Test vectors from ~/avatar/src/tck/test_vectors/keccak256.yaml */

#include "at/crypto/at_keccak256.h"
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

/* Keccak256 test vector structure */
typedef struct {
  char const * name;
  char const * input_hex;
  ulong        input_length;
  char const * expected_hex;
} test_vector_t;

/* Keccak256 test vectors from src/tck/test_vectors/keccak256.yaml */
static test_vector_t const test_vectors[] = {
  { "empty_string", "", 0,
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" },
  { "abc", "616263", 3,
    "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45" },
  { "hello_world", "48656c6c6f2c20776f726c6421", 13,
    "b6e16d27ac5ab427a7f68900ac5559ce272dc6c37c82b3e052246c82244c50e4" },
  { "eth_pubkey_64bytes",
    "04040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404",
    64,
    "d73222fc071b1494828915725ec7529be23fdfd2c28075be3e06dcab3c7d62c5" },
  { "135_bytes_a",
    "616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161",
    135,
    "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446" },
  { "136_bytes_a",
    "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161",
    136,
    "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e" },
};

#define TEST_VECTOR_CNT (sizeof(test_vectors)/sizeof(test_vectors[0]))

/* Test reference Keccak256 hash matches expected */
static int
test_keccak256_reference( test_vector_t const * tv ) {
  uchar input[256];
  uchar expected[32];
  uchar hash[32];

  int input_sz = hex_to_bytes( tv->input_hex, input, sizeof(input) );
  if( input_sz < 0 ) input_sz = 0;
  hex_to_bytes( tv->expected_hex, expected, 32 );

  at_keccak256_hash( input, (ulong)input_sz, hash );

  if( at_memcmp( hash, expected, 32 ) != 0 ) {
    printf( "FAIL: keccak256_reference_%s\n", tv->name );
    printf( "  Expected: %s\n", tv->expected_hex );
    printf( "  Got:      " );
    print_hex( hash, 32 );
    printf( "\n" );
    return 1;
  }

  printf( "PASS: keccak256_reference_%s\n", tv->name );
  return 0;
}

/* Test batch Keccak256 hash matches reference */
static int
test_keccak256_batch_vs_reference( void ) {
  int fail = 0;

  uchar inputs[TEST_VECTOR_CNT][256];
  uchar ref_hashes[TEST_VECTOR_CNT][32];
  uchar batch_hashes[TEST_VECTOR_CNT][32];

  /* Compute reference hashes */
  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    int sz = hex_to_bytes( test_vectors[i].input_hex, inputs[i], sizeof(inputs[i]) );
    ulong input_sz = (sz < 0) ? 0 : (ulong)sz;
    at_keccak256_hash( inputs[i], input_sz, ref_hashes[i] );
  }

  /* Compute batch hashes */
  uchar batch_mem[ AT_KECCAK256_BATCH_FOOTPRINT ] __attribute__((aligned(AT_KECCAK256_BATCH_ALIGN)));
  at_keccak256_batch_t * batch = at_keccak256_batch_init( batch_mem );

  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    int sz = hex_to_bytes( test_vectors[i].input_hex, inputs[i], sizeof(inputs[i]) );
    ulong input_sz = (sz < 0) ? 0 : (ulong)sz;
    batch = at_keccak256_batch_add( batch, inputs[i], input_sz, batch_hashes[i] );
  }

  at_keccak256_batch_fini( batch );

  /* Compare */
  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    if( at_memcmp( batch_hashes[i], ref_hashes[i], 32 ) != 0 ) {
      printf( "FAIL: keccak256_batch_vs_ref_%s\n", test_vectors[i].name );
      printf( "  Reference: " );
      print_hex( ref_hashes[i], 32 );
      printf( "\n  Batch:     " );
      print_hex( batch_hashes[i], 32 );
      printf( "\n" );
      fail++;
    } else {
      printf( "PASS: keccak256_batch_vs_ref_%s\n", test_vectors[i].name );
    }
  }

  return fail;
}

/* Test batch with varying batch sizes */
static int
test_keccak256_batch_sizes( void ) {
  int fail = 0;

  uchar input[64];
  at_memset( input, 0x42, 64 );

  uchar ref_hash[32];
  at_keccak256_hash( input, 64, ref_hash );

  for( ulong batch_cnt = 1; batch_cnt <= AT_KECCAK256_BATCH_MAX; batch_cnt++ ) {
    uchar batch_hashes[AT_KECCAK256_BATCH_MAX][32];

    uchar batch_mem[ AT_KECCAK256_BATCH_FOOTPRINT ] __attribute__((aligned(AT_KECCAK256_BATCH_ALIGN)));
    at_keccak256_batch_t * batch = at_keccak256_batch_init( batch_mem );

    for( ulong i = 0; i < batch_cnt; i++ ) {
      batch = at_keccak256_batch_add( batch, input, 64, batch_hashes[i] );
    }

    at_keccak256_batch_fini( batch );

    int batch_ok = 1;
    for( ulong i = 0; i < batch_cnt; i++ ) {
      if( at_memcmp( batch_hashes[i], ref_hash, 32 ) != 0 ) {
        batch_ok = 0;
        break;
      }
    }

    if( !batch_ok ) {
      printf( "FAIL: keccak256_batch_size_%lu\n", batch_cnt );
      fail++;
    } else {
      printf( "PASS: keccak256_batch_size_%lu\n", batch_cnt );
    }
  }

  return fail;
}

/* Test batch with mixed message sizes */
static int
test_keccak256_batch_mixed_sizes( void ) {
  int fail = 0;

  uchar inputs[AT_KECCAK256_BATCH_MAX][256];
  ulong sizes[AT_KECCAK256_BATCH_MAX];
  uchar ref_hashes[AT_KECCAK256_BATCH_MAX][32];
  uchar batch_hashes[AT_KECCAK256_BATCH_MAX][32];

  ulong test_sizes[] = { 0, 1, 32, 64, 100, 135, 136, 200 };
  ulong num_tests = AT_KECCAK256_BATCH_MAX;
  if( num_tests > sizeof(test_sizes)/sizeof(test_sizes[0]) ) {
    num_tests = sizeof(test_sizes)/sizeof(test_sizes[0]);
  }

  for( ulong i = 0; i < num_tests; i++ ) {
    sizes[i] = test_sizes[i];
    at_memset( inputs[i], (uchar)(0x30 + i), sizes[i] );
    at_keccak256_hash( inputs[i], sizes[i], ref_hashes[i] );
  }

  uchar batch_mem[ AT_KECCAK256_BATCH_FOOTPRINT ] __attribute__((aligned(AT_KECCAK256_BATCH_ALIGN)));
  at_keccak256_batch_t * batch = at_keccak256_batch_init( batch_mem );

  for( ulong i = 0; i < num_tests; i++ ) {
    batch = at_keccak256_batch_add( batch, inputs[i], sizes[i], batch_hashes[i] );
  }

  at_keccak256_batch_fini( batch );

  int all_match = 1;
  for( ulong i = 0; i < num_tests; i++ ) {
    if( at_memcmp( batch_hashes[i], ref_hashes[i], 32 ) != 0 ) {
      all_match = 0;
      printf( "FAIL: keccak256_batch_mixed_size_%lu (size=%lu)\n", i, sizes[i] );
      fail++;
    }
  }

  if( all_match ) {
    printf( "PASS: keccak256_batch_mixed_sizes (all %lu sizes match)\n", num_tests );
  }

  return fail;
}

/* Test consistency */
static int
test_keccak256_consistency( void ) {
  int fail = 0;

  uchar input[128];
  at_memset( input, 0xAB, 128 );

  uchar hash1[32], hash2[32];

  /* First batch */
  uchar batch_mem1[ AT_KECCAK256_BATCH_FOOTPRINT ] __attribute__((aligned(AT_KECCAK256_BATCH_ALIGN)));
  at_keccak256_batch_t * batch1 = at_keccak256_batch_init( batch_mem1 );
  batch1 = at_keccak256_batch_add( batch1, input, 128, hash1 );
  at_keccak256_batch_fini( batch1 );

  /* Second batch */
  uchar batch_mem2[ AT_KECCAK256_BATCH_FOOTPRINT ] __attribute__((aligned(AT_KECCAK256_BATCH_ALIGN)));
  at_keccak256_batch_t * batch2 = at_keccak256_batch_init( batch_mem2 );
  batch2 = at_keccak256_batch_add( batch2, input, 128, hash2 );
  at_keccak256_batch_fini( batch2 );

  if( at_memcmp( hash1, hash2, 32 ) != 0 ) {
    printf( "FAIL: keccak256_consistency\n" );
    fail++;
  } else {
    printf( "PASS: keccak256_consistency\n" );
  }

  return fail;
}

int main( void ) {
  int fail = 0;

  printf( "=== Keccak256 Reference Tests ===\n" );
  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    fail += test_keccak256_reference( &test_vectors[i] );
  }

  printf( "\n=== Keccak256 Batch vs Reference Tests ===\n" );
  fail += test_keccak256_batch_vs_reference();

  printf( "\n=== Keccak256 Batch Size Tests ===\n" );
  fail += test_keccak256_batch_sizes();

  printf( "\n=== Keccak256 Mixed Size Batch Test ===\n" );
  fail += test_keccak256_batch_mixed_sizes();

  printf( "\n=== Keccak256 Consistency Tests ===\n" );
  fail += test_keccak256_consistency();

  printf( "\n%d total failures\n", fail );
  printf( "%s\n", fail ? "SOME TESTS FAILED" : "ALL TESTS PASSED" );

  return fail;
}
