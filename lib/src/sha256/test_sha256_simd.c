/* SHA256 SIMD Equivalence Tests
   Tests that SIMD batch implementations produce identical results to reference.
   Test vectors from ~/avatar/src/tck/test_vectors/sha256.yaml */

#include "at/crypto/at_sha256.h"
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

/* Test vectors from src/tck/test_vectors/sha256.yaml */
static test_vector_t const test_vectors[] = {
  { "empty_string", "", 0,
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
  { "abc", "616263", 3,
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
  { "hello_world", "48656c6c6f2c20776f726c6421", 13,
    "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3" },
  { "55_bytes_a", "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161", 55,
    "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318" },
  { "56_bytes_a", "6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161", 56,
    "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a" },
  { "64_bytes_a", "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161", 64,
    "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb" },
  { "128_bytes_a", "6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161", 128,
    "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e" },
  { "nist_vector", "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071", 56,
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
};

#define TEST_VECTOR_CNT (sizeof(test_vectors)/sizeof(test_vectors[0]))

/* Test single reference hash matches expected */
static int
test_reference( test_vector_t const * tv ) {
  uchar input[256];
  uchar expected[32];
  uchar hash[32];

  int input_sz = hex_to_bytes( tv->input_hex, input, sizeof(input) );
  if( input_sz < 0 ) input_sz = 0;
  hex_to_bytes( tv->expected_hex, expected, 32 );

  at_sha256_hash( input, (ulong)input_sz, hash );

  if( at_memcmp( hash, expected, 32 ) != 0 ) {
    printf( "FAIL: reference_%s\n", tv->name );
    printf( "  Expected: %s\n", tv->expected_hex );
    printf( "  Got:      " );
    print_hex( hash, 32 );
    printf( "\n" );
    return 1;
  }

  printf( "PASS: reference_%s\n", tv->name );
  return 0;
}

/* Test batch hash matches reference hash */
static int
test_batch_vs_reference( void ) {
  int fail = 0;

  /* Prepare batch inputs */
  uchar inputs[TEST_VECTOR_CNT][256];
  uchar ref_hashes[TEST_VECTOR_CNT][32];
  uchar batch_hashes[TEST_VECTOR_CNT][32];

  /* Compute reference hashes */
  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    int sz = hex_to_bytes( test_vectors[i].input_hex, inputs[i], sizeof(inputs[i]) );
    ulong input_sz = (sz < 0) ? 0 : (ulong)sz;
    at_sha256_hash( inputs[i], input_sz, ref_hashes[i] );
  }

  /* Compute batch hashes using batch API */
  uchar batch_mem[ 1024 ] __attribute__((aligned(128)));
  at_sha256_batch_t * batch = at_sha256_batch_init( batch_mem );

  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    int sz = hex_to_bytes( test_vectors[i].input_hex, inputs[i], sizeof(inputs[i]) );
    ulong input_sz = (sz < 0) ? 0 : (ulong)sz;
    batch = at_sha256_batch_add( batch, inputs[i], input_sz, batch_hashes[i] );
  }

  at_sha256_batch_fini( batch );

  /* Compare batch results with reference */
  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    if( at_memcmp( batch_hashes[i], ref_hashes[i], 32 ) != 0 ) {
      printf( "FAIL: batch_vs_ref_%s\n", test_vectors[i].name );
      printf( "  Reference: " );
      print_hex( ref_hashes[i], 32 );
      printf( "\n  Batch:     " );
      print_hex( batch_hashes[i], 32 );
      printf( "\n" );
      fail++;
    } else {
      printf( "PASS: batch_vs_ref_%s\n", test_vectors[i].name );
    }
  }

  return fail;
}

/* Test batch with different batch sizes (1 to 8) */
static int
test_batch_sizes( void ) {
  int fail = 0;

  uchar input[64];
  at_memset( input, 0x42, 64 );

  uchar ref_hash[32];
  at_sha256_hash( input, 64, ref_hash );

  for( ulong batch_cnt = 1; batch_cnt <= 8; batch_cnt++ ) {
    uchar batch_hashes[8][32];

    /* Run batch */
    uchar batch_mem[ 1024 ] __attribute__((aligned(128)));
    at_sha256_batch_t * batch = at_sha256_batch_init( batch_mem );

    for( ulong i = 0; i < batch_cnt; i++ ) {
      batch = at_sha256_batch_add( batch, input, 64, batch_hashes[i] );
    }

    at_sha256_batch_fini( batch );

    /* Verify all match reference */
    int batch_ok = 1;
    for( ulong i = 0; i < batch_cnt; i++ ) {
      if( at_memcmp( batch_hashes[i], ref_hash, 32 ) != 0 ) {
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

  uchar inputs[8][256];
  ulong sizes[] = { 0, 1, 32, 55, 56, 64, 100, 128 };
  uchar ref_hashes[8][32];
  uchar batch_hashes[8][32];

  for( ulong i = 0; i < 8; i++ ) {
    at_memset( inputs[i], (uchar)(0x30 + i), sizes[i] );
    at_sha256_hash( inputs[i], sizes[i], ref_hashes[i] );
  }

  uchar batch_mem[ 1024 ] __attribute__((aligned(128)));
  at_sha256_batch_t * batch = at_sha256_batch_init( batch_mem );

  for( ulong i = 0; i < 8; i++ ) {
    batch = at_sha256_batch_add( batch, inputs[i], sizes[i], batch_hashes[i] );
  }

  at_sha256_batch_fini( batch );

  int all_match = 1;
  for( ulong i = 0; i < 8; i++ ) {
    if( at_memcmp( batch_hashes[i], ref_hashes[i], 32 ) != 0 ) {
      all_match = 0;
      printf( "FAIL: batch_mixed_size_%lu (size=%lu)\n", i, sizes[i] );
      fail++;
    }
  }

  if( all_match ) {
    printf( "PASS: batch_mixed_sizes (all 8 sizes match)\n" );
  }

  return fail;
}

int main( void ) {
  int fail = 0;

  printf( "=== SHA256 Reference Tests ===\n" );
  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    fail += test_reference( &test_vectors[i] );
  }

  printf( "\n=== SHA256 Batch vs Reference Tests ===\n" );
  fail += test_batch_vs_reference();

  printf( "\n=== SHA256 Batch Size Tests ===\n" );
  fail += test_batch_sizes();

  printf( "\n=== SHA256 Mixed Size Batch Test ===\n" );
  fail += test_batch_mixed_sizes();

  printf( "\n%d total tests, %d failures\n",
          (int)(TEST_VECTOR_CNT + TEST_VECTOR_CNT + 8 + 1), fail );
  printf( "%s\n", fail ? "SOME TESTS FAILED" : "ALL TESTS PASSED" );

  return fail;
}
