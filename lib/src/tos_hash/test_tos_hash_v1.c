/* test_tos_hash_v1.c - Validate C v1 implementation against Rust vectors */

#include "at/crypto/at_tos_hash_v1.h"
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
test_zero_input( void ) {
  uchar input[AT_TOS_HASH_V1_INPUT_SZ];
  uchar out[32];
  uchar expected[32] = {
    0x0e,0xbb,0xbd,0x8a,0x31,0xed,0xad,0xfe,
    0x09,0x8f,0x2d,0x77,0x0d,0x84,0xb7,0x19,
    0x58,0x86,0x75,0xab,0x88,0xa0,0xa1,0x70,
    0x67,0xd0,0x0a,0x8f,0x36,0x18,0x22,0x65
  };
  at_tos_hash_v1_scratch_t scratch[1];

  at_memset( input, 0, sizeof(input) );
  at_tos_hash_v1_scratch_init( scratch );
  CHECK( !at_tos_hash_v1_hash( input, sizeof(input), out, scratch ), "v1 zero hash" );
  CHECK( !at_memcmp( out, expected, 32 ), "v1 zero vector" );
}

static void
test_tos_input( void ) {
  uchar input[AT_TOS_HASH_V1_INPUT_SZ];
  uchar out_a[32];
  uchar out_b[32];
  uchar expected[32] = {
    101,187,11,129,231,6,148,2,28,63,115,103,25,58,27,247,
    16,212,243,130,2,129,250,71,173,243,230,141,40,53,53,157
  };
  char const * msg = "tos-hashing-algorithm";
  at_tos_hash_v1_scratch_t scratch[1];

  at_memset( input, 0, sizeof(input) );
  at_memcpy( input, msg, at_strlen( msg ) );

  at_tos_hash_v1_scratch_init( scratch );
  CHECK( !at_tos_hash_v1_hash( input, sizeof(input), out_a, scratch ), "v1 tos hash first" );
  CHECK( !at_tos_hash_v1_hash( input, sizeof(input), out_b, scratch ), "v1 tos hash second" );
  CHECK( !at_memcmp( out_a, expected, 32 ), "v1 tos vector" );
  CHECK( !at_memcmp( out_a, out_b, 32 ), "v1 deterministic with scratch reuse" );
}

int
main( void ) {
  test_zero_input();
  test_tos_input();

  if( g_fail ) return 1;
  printf( "PASS test_tos_hash_v1\n" );
  return 0;
}

