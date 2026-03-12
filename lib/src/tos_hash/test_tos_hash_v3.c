/* test_tos_hash_v3.c - Validate C v3 implementation against Rust YAML vectors */

#include "at/crypto/at_tos_hash_v3.h"
#include "at/infra/at_yaml.h"
#include <stdio.h>

static void
print_hex( uchar const * data,
           ulong         sz ) {
  for( ulong i = 0; i < sz; i++ ) printf( "%02x", data[i] );
}

static int
test_vector( at_yaml_obj_t const * vec ) {
  char const * name = at_yaml_obj_get_string( vec, "name" );
  char const * input_hex = at_yaml_obj_get_string( vec, "input_hex" );
  long         input_len = at_yaml_obj_get_int( vec, "input_len", -1 );
  char const * expected_hex = at_yaml_obj_get_string( vec, "expected_hash_hex" );

  if( !name || !input_hex || !expected_hex || input_len < 0 ) {
    printf( "SKIP: missing required fields\n" );
    return 0;
  }

  uchar input[4096];
  int input_sz = at_yaml_hex_to_bytes( input, sizeof(input), input_hex );
  if( input_sz < 0 ) {
    printf( "FAIL: %s - invalid input_hex\n", name );
    return 1;
  }
  if( input_sz != (int)input_len ) {
    printf( "FAIL: %s - input_len mismatch (yaml=%ld decoded=%d)\n", name, input_len, input_sz );
    return 1;
  }

  uchar expected[32];
  if( at_yaml_hex_to_bytes( expected, sizeof(expected), expected_hex ) != 32 ) {
    printf( "FAIL: %s - invalid expected_hash_hex\n", name );
    return 1;
  }

  at_tos_hash_v3_scratch_t scratch[1];
  uchar out_a[32];
  uchar out_b[32];

  at_tos_hash_v3_scratch_init( scratch );
  if( at_tos_hash_v3_hash( input, (ulong)input_sz, out_a, scratch ) ) {
    printf( "FAIL: %s - hashing failed\n", name );
    return 1;
  }

  if( at_tos_hash_v3_hash( input, (ulong)input_sz, out_b, scratch ) ) {
    printf( "FAIL: %s - second hashing failed\n", name );
    return 1;
  }

  if( at_memcmp( out_a, expected, 32 ) ) {
    printf( "FAIL: %s - hash mismatch\n", name );
    printf( "  Expected: %s\n", expected_hex );
    printf( "  Got:      " ); print_hex( out_a, 32 ); printf( "\n" );
    return 1;
  }

  if( at_memcmp( out_a, out_b, 32 ) ) {
    printf( "FAIL: %s - nondeterministic result with scratch reuse\n", name );
    return 1;
  }

  printf( "PASS: %s\n", name );
  return 0;
}

int
main( int    argc,
      char * argv[] ) {
  char const * yaml_path = "src/tck/test_vectors/tos_hash_v3.yaml";
  if( argc > 1 ) yaml_path = argv[1];

  printf( "=== TOS Hash V3 YAML Tests ===\n" );
  printf( "Loading: %s\n\n", yaml_path );

  static _Thread_local at_yaml_doc_t doc; /* IMPORTANT: large parser state, keep static */
  if( at_yaml_parse_file( &doc, yaml_path ) != 0 ) {
    printf( "FAIL: Could not parse YAML file: %s\n", yaml_path );
    return 1;
  }

  char const * algo = at_yaml_get_string( &doc, "algorithm" );
  if( !algo || at_strcmp( algo, "TOS_HASH_V3" ) ) {
    printf( "FAIL: algorithm should be TOS_HASH_V3\n" );
    return 1;
  }

  at_yaml_array_t const * vectors = at_yaml_get_array( &doc, "test_vectors" );
  if( !vectors ) {
    printf( "FAIL: test_vectors array not found\n" );
    return 1;
  }

  int fail = 0;
  for( int i = 0; i < vectors->item_count; i++ ) {
    fail += test_vector( &vectors->items[i] );
  }

  printf( "\n%d tests, %d failed\n", vectors->item_count, fail );
  printf( "%s\n", fail ? "SOME TESTS FAILED" : "ALL TESTS PASSED - TOS Rust == Avatar C" );
  return fail;
}
