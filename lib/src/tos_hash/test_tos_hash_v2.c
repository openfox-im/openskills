/* test_tos_hash_v2.c - Validate C v2 implementation against Rust vectors */

#include "at/crypto/at_tos_hash_v2.h"
#include <stdio.h>

static int g_fail = 0;

#define CHECK(COND, MSG) do {                                                \
  if( !(COND) ) {                                                             \
    fprintf( stderr, "FAIL: %s (%s:%d)\n", (MSG), __FILE__, __LINE__ );      \
    g_fail = 1;                                                               \
    return;                                                                   \
  }                                                                           \
} while(0)

static void
test_vector_zero_112( void ) {
  uchar input[112];
  uchar out[32];
  uchar expected[32] = {
    0xcb, 0xfc, 0x8a, 0xa5, 0x07, 0x04, 0xce, 0xc4,
    0x36, 0xd5, 0x2c, 0xbb, 0xd0, 0x75, 0x0d, 0x9a,
    0xf2, 0x74, 0x59, 0x1b, 0xf8, 0xfb, 0x94, 0x2e,
    0x2f, 0xdb, 0x93, 0xe5, 0x1d, 0x7f, 0x09, 0xe2
  };
  at_tos_hash_v2_scratch_t scratch[1];

  at_memset( input, 0, sizeof(input) );
  at_tos_hash_v2_scratch_init( scratch );
  CHECK( !at_tos_hash_v2_hash( input, sizeof(input), out, scratch ), "v2 zero hash" );
  CHECK( !at_memcmp( out, expected, 32 ), "v2 zero vector" );
}

static void
test_vector_known_input( void ) {
  uchar const input[112] = {
    172,236,108,212,181,31,109,45,44,242,54,225,143,133,89,44,
    179,108,39,191,32,116,229,33,63,130,33,120,185,89,146,141,
    10,79,183,107,238,122,92,222,25,134,90,107,116,110,236,53,
    255,5,214,126,24,216,97,199,148,239,253,102,199,184,232,253,
    158,145,86,187,112,81,78,70,80,110,33,37,159,233,198,1,
    178,108,210,100,109,155,106,124,124,83,89,50,197,115,231,32,
    74,2,92,47,25,220,135,249,122,172,220,137,143,234,68,188
  };
  uchar out[32];
  uchar expected[32] = {
    0xdc, 0x1c, 0x28, 0x1d, 0x03, 0xbc, 0xd8, 0xfa,
    0x41, 0x75, 0x1c, 0xf1, 0x47, 0x5a, 0xf1, 0xf2,
    0x31, 0xbd, 0x0b, 0xf6, 0xfa, 0x99, 0x52, 0x78,
    0x83, 0x77, 0xbc, 0x1d, 0xbb, 0xfc, 0x6d, 0x38
  };
  at_tos_hash_v2_scratch_t scratch[1];
  uchar out2[32];

  at_tos_hash_v2_scratch_init( scratch );
  CHECK( !at_tos_hash_v2_hash( input, sizeof(input), out, scratch ), "v2 known hash first" );
  CHECK( !at_tos_hash_v2_hash( input, sizeof(input), out2, scratch ), "v2 known hash second" );
  CHECK( !at_memcmp( out, expected, 32 ), "v2 known vector" );
  CHECK( !at_memcmp( out, out2, 32 ), "v2 deterministic with scratch reuse" );
}

int
main( void ) {
  test_vector_zero_112();
  test_vector_known_input();

  if( g_fail ) return 1;
  printf( "PASS test_tos_hash_v2\n" );
  return 0;
}

