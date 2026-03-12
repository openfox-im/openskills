/* SHA3-512 test vectors from TOS TCK
   Test vectors generated from Rust sha3 crate v0.10 (same as TOS uses)
   See: ~/tos/tck/crypto/sha3_512.yaml */

#include "at_sha3.h"
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

static int
test_vector( char const * name,
             uchar const * input,
             ulong         input_sz,
             char const *  expected_hex ) {
  uchar expected[64];
  uchar hash[64];

  hex_to_bytes( expected_hex, expected, 64 );
  at_sha3_512_hash( input, input_sz, hash );

  if( at_memcmp( hash, expected, 64 ) != 0 ) {
    printf( "FAIL: %s\n", name );
    printf( "  Expected: %s\n", expected_hex );
    printf( "  Got:      " );
    print_hex( hash, 64 );
    printf( "\n" );
    return 1;
  }

  printf( "PASS: %s\n", name );
  return 0;
}

int main( void ) {
  int fail = 0;

  /* Test vectors from ~/tos/tck/crypto/sha3_512.yaml */

  /* 1. empty_string */
  fail += test_vector( "empty_string",
    (uchar const *)"", 0,
    "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
    "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26" );

  /* 2. abc */
  fail += test_vector( "abc",
    (uchar const *)"abc", 3,
    "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
    "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0" );

  /* 3. hello_world - Message used in TOS signature tests */
  fail += test_vector( "hello_world",
    (uchar const *)"Hello, world!", 13,
    "8e47f1185ffd014d238fabd02a1a32defe698cbf38c037a90e3c0a0a32370fb5"
    "2cbd641250508502295fcabcbf676c09470b27443868c8e5f70e26dc337288af" );

  /* 4. 71_bytes_a - One byte less than SHA3-512 block size */
  {
    uchar input[71];
    at_memset( input, 0x61, 71 );
    fail += test_vector( "71_bytes_a", input, 71,
      "070faf98d2a8fddf8ed886408744dc06456096c2e045f26f3c7b010530e6bbb3"
      "db535a54d636856f4e0e1e982461cb9a7e8e57ff8895cff1619af9f0e486e28c" );
  }

  /* 5. 72_bytes_a - Exactly one SHA3-512 block (72 bytes) */
  {
    uchar input[72];
    at_memset( input, 0x61, 72 );
    fail += test_vector( "72_bytes_a", input, 72,
      "a8ae722a78e10cbbc413886c02eb5b369a03f6560084aff566bd597bb7ad8c1c"
      "cd86e81296852359bf2faddb5153c0a7445722987875e74287adac21adebe952" );
  }

  /* 6. 73_bytes_a - One byte more than SHA3-512 block size */
  {
    uchar input[73];
    at_memset( input, 0x61, 73 );
    fail += test_vector( "73_bytes_a", input, 73,
      "23e6a8815f8201dbbf6a5463be8dcadb1acea9df5f8998954e59ac9565cf6d29"
      "b17aa27a5e8b0fc06343db6122d6e544d27583ddc78504d08203217e7e65b6bd" );
  }

  /* 7. 144_bytes_a - Exactly two SHA3-512 blocks (144 bytes) */
  {
    uchar input[144];
    at_memset( input, 0x61, 144 );
    fail += test_vector( "144_bytes_a", input, 144,
      "446cd4d7ba19510dcc776b21045bc68d424b5b840e14685e149bb238b5f473c0"
      "356b69e04f0f5785eefce20ff09e678b080d8aac64568c5edf001cd32b2ed7a8" );
  }

  /* 8. tos_signature_hash - TOS hash_and_point_to_scalar style input */
  {
    uchar input[77];
    at_memset( input, 0, 32 );                              /* pubkey: 32 zeros */
    at_memcpy( input + 32, "Hello, world!", 13 );           /* message */
    at_memset( input + 32 + 13, 0, 32 );                    /* point: 32 zeros */
    fail += test_vector( "tos_signature_hash", input, 77,
      "e3781444a37d142f691f78de737f3ae1dce26184432a218563477d332555ca2d"
      "84e63b32d5faa6c1d1842018341a60ebafcadd90a736a935b07e6e7061ce3ca8" );
  }

  /* 9. streaming API test - same result when appending in chunks */
  {
    at_sha3_512_t sha[1];
    uchar hash[64];
    uchar expected[64];
    hex_to_bytes(
      "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
      "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
      expected, 64 );

    at_sha3_512_init( sha );
    at_sha3_512_append( sha, "a", 1 );
    at_sha3_512_append( sha, "bc", 2 );
    at_sha3_512_fini( sha, hash );

    if( at_memcmp( hash, expected, 64 ) != 0 ) {
      printf( "FAIL: streaming_api\n" );
      fail++;
    } else {
      printf( "PASS: streaming_api\n" );
    }
  }

  printf( "\n%d tests, %d failed\n", 9, fail );
  printf( "%s\n", fail ? "SOME TESTS FAILED" : "ALL TESTS PASSED" );
  return fail;
}