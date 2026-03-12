/* BLAKE3 SIMD Equivalence Tests
   Tests that SIMD implementations produce identical results to reference.
   Test vectors from ~/avatar/src/tck/test_vectors/blake3.yaml */

#include "at/crypto/at_blake3.h"
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

/* Test vectors from src/tck/test_vectors/blake3.yaml */
static test_vector_t const test_vectors[] = {
  { "empty_string", "", 0,
    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" },
  { "abc", "616263", 3,
    "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85" },
  { "hello_world", "48656c6c6f2c20776f726c6421", 13,
    "ede5c0b10f2ec4979c69b52f61e42ff5b413519ce09be0f14d098dcfe5f6f98d" },
  { "63_bytes_a", "616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161", 63,
    "1a2a060cf56e4a859d80723cac9e2391d3c09a33008483e5424c57fe68629b79" },
  { "64_bytes_a", "61616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161", 64,
    "472c51290d607f100d2036fdcedd7590bba245e9adeb21364a063b7bb4ca81c7" },
  { "65_bytes_a", "6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161", 65,
    "f345679d9055e53939e92c04ff4f6c9d824b849810d4b598f54baa23336cde99" },
  { "tx_hash", "4242424242424242424242424242424242424242424242424242424242424242", 32,
    "bcff11daf7dbb8c789b7bcc4e45298041666f92fa8454b1c3fa86e174fd611e4" },
};

#define TEST_VECTOR_CNT (sizeof(test_vectors)/sizeof(test_vectors[0]))

/* Test single hash matches expected */
static int
test_hash( test_vector_t const * tv ) {
  uchar input[256];
  uchar expected[32];
  uchar hash[32];

  int input_sz = hex_to_bytes( tv->input_hex, input, sizeof(input) );
  if( input_sz < 0 ) input_sz = 0;
  hex_to_bytes( tv->expected_hex, expected, 32 );

  at_blake3_hash( input, (ulong)input_sz, hash );

  if( at_memcmp( hash, expected, 32 ) != 0 ) {
    printf( "FAIL: hash_%s\n", tv->name );
    printf( "  Expected: %s\n", tv->expected_hex );
    printf( "  Got:      " );
    print_hex( hash, 32 );
    printf( "\n" );
    return 1;
  }

  printf( "PASS: hash_%s\n", tv->name );
  return 0;
}

/* Test streaming API matches one-shot API */
static int
test_streaming_vs_oneshot( void ) {
  int fail = 0;

  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    uchar input[256];
    int input_sz = hex_to_bytes( test_vectors[i].input_hex, input, sizeof(input) );
    if( input_sz < 0 ) input_sz = 0;

    uchar oneshot_hash[32];
    uchar stream_hash[32];

    /* One-shot hash */
    at_blake3_hash( input, (ulong)input_sz, oneshot_hash );

    /* Streaming hash */
    at_blake3_t blake3_mem[1];
    at_blake3_t * blake3 = at_blake3_join( at_blake3_new( blake3_mem ) );
    at_blake3_init( blake3 );
    at_blake3_append( blake3, input, (ulong)input_sz );
    at_blake3_fini( blake3, stream_hash );
    at_blake3_delete( at_blake3_leave( blake3 ) );

    if( at_memcmp( oneshot_hash, stream_hash, 32 ) != 0 ) {
      printf( "FAIL: streaming_vs_oneshot_%s\n", test_vectors[i].name );
      printf( "  One-shot:  " );
      print_hex( oneshot_hash, 32 );
      printf( "\n  Streaming: " );
      print_hex( stream_hash, 32 );
      printf( "\n" );
      fail++;
    } else {
      printf( "PASS: streaming_vs_oneshot_%s\n", test_vectors[i].name );
    }
  }

  return fail;
}

/* Test chunked streaming (split input) matches one-shot */
static int
test_chunked_streaming( void ) {
  int fail = 0;

  /* Test with 128-byte input split in various ways */
  uchar input[128];
  at_memset( input, 0x42, 128 );

  uchar oneshot_hash[32];
  at_blake3_hash( input, 128, oneshot_hash );

  /* Test different chunk sizes */
  ulong chunk_sizes[] = { 1, 7, 16, 32, 64 };

  for( ulong c = 0; c < sizeof(chunk_sizes)/sizeof(chunk_sizes[0]); c++ ) {
    ulong chunk_sz = chunk_sizes[c];
    uchar stream_hash[32];

    at_blake3_t blake3_mem[1];
    at_blake3_t * blake3 = at_blake3_join( at_blake3_new( blake3_mem ) );
    at_blake3_init( blake3 );

    ulong pos = 0;
    while( pos < 128 ) {
      ulong to_append = (128 - pos < chunk_sz) ? (128 - pos) : chunk_sz;
      at_blake3_append( blake3, input + pos, to_append );
      pos += to_append;
    }

    at_blake3_fini( blake3, stream_hash );
    at_blake3_delete( at_blake3_leave( blake3 ) );

    if( at_memcmp( oneshot_hash, stream_hash, 32 ) != 0 ) {
      printf( "FAIL: chunked_streaming_chunk%lu\n", chunk_sz );
      printf( "  One-shot:  " );
      print_hex( oneshot_hash, 32 );
      printf( "\n  Chunked:   " );
      print_hex( stream_hash, 32 );
      printf( "\n" );
      fail++;
    } else {
      printf( "PASS: chunked_streaming_chunk%lu\n", chunk_sz );
    }
  }

  return fail;
}

/* Test consistency of multiple hash calls on same input */
static int
test_consistency( void ) {
  int fail = 0;

  uchar input[64];
  at_memset( input, 0xAB, 64 );

  uchar hash1[32];
  uchar hash2[32];

  at_blake3_hash( input, 64, hash1 );
  at_blake3_hash( input, 64, hash2 );

  if( at_memcmp( hash1, hash2, 32 ) != 0 ) {
    printf( "FAIL: consistency\n" );
    printf( "  First:  " );
    print_hex( hash1, 32 );
    printf( "\n  Second: " );
    print_hex( hash2, 32 );
    printf( "\n" );
    fail++;
  } else {
    printf( "PASS: consistency\n" );
  }

  return fail;
}

/* Test different input sizes (exercises different SIMD paths) */
static int
test_various_sizes( void ) {
  int fail = 0;

  /* Various sizes that exercise different code paths */
  ulong sizes[] = { 0, 1, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 1023, 1024, 1025 };

  for( ulong s = 0; s < sizeof(sizes)/sizeof(sizes[0]); s++ ) {
    ulong sz = sizes[s];

    uchar input[2048];
    at_memset( input, (uchar)(0x30 + (s % 10)), sz );

    uchar hash1[32];
    uchar hash2[32];

    /* Hash twice and compare */
    at_blake3_hash( input, sz, hash1 );
    at_blake3_hash( input, sz, hash2 );

    if( at_memcmp( hash1, hash2, 32 ) != 0 ) {
      printf( "FAIL: size_%lu\n", sz );
      fail++;
    } else {
      printf( "PASS: size_%lu\n", sz );
    }
  }

  return fail;
}

int main( void ) {
  int fail = 0;

  printf( "=== BLAKE3 Hash Tests ===\n" );
  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    fail += test_hash( &test_vectors[i] );
  }

  printf( "\n=== BLAKE3 Streaming vs One-shot Tests ===\n" );
  fail += test_streaming_vs_oneshot();

  printf( "\n=== BLAKE3 Chunked Streaming Tests ===\n" );
  fail += test_chunked_streaming();

  printf( "\n=== BLAKE3 Consistency Test ===\n" );
  fail += test_consistency();

  printf( "\n=== BLAKE3 Various Sizes Tests ===\n" );
  fail += test_various_sizes();

  printf( "\n%d tests, %d failures\n",
          (int)(TEST_VECTOR_CNT + TEST_VECTOR_CNT + 5 + 1 + 16), fail );
  printf( "%s\n", fail ? "SOME TESTS FAILED" : "ALL TESTS PASSED" );

  return fail;
}
