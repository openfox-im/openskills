/* SHA1 test vectors from RFC 3174 */

#include "at/crypto/at_sha1.h"
#include "at/infra/at_util.h"
#include <stdio.h>
#include <string.h>

static void
print_hash( char const * label, uchar const hash[20] ) {
  printf( "%s: ", label );
  for( ulong i = 0; i < 20; i++ ) {
    printf( "%02x", hash[i] );
  }
  printf( "\n" );
}

static int
test_vector( char const * input,
             char const * expected_hex ) {
  uchar hash[20];
  at_sha1_hash( (uchar const *)input, strlen(input), hash );

  /* Convert hash to hex string */
  char hash_hex[41];
  for( ulong i = 0; i < 20; i++ ) {
    snprintf( hash_hex + i*2, 3, "%02x", hash[i] );
  }
  hash_hex[40] = '\0';

  if( strcmp( hash_hex, expected_hex ) != 0 ) {
    printf( "FAIL: %s\n", input );
    printf( "  Expected: %s\n", expected_hex );
    printf( "  Got:      %s\n", hash_hex );
    return -1;
  }

  printf( "PASS: %s\n", input );
  return 0;
}

int
main( int argc, char ** argv ) {
  (void)argc;
  (void)argv;

  int failures = 0;

  /* RFC 3174 Test Vector 1: "abc" */
  failures += test_vector(
    "abc",
    "a9993e364706816aba3e25717850c26c9cd0d89d"
  );

  /* RFC 3174 Test Vector 2: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
  failures += test_vector(
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
  );

  /* Empty string */
  failures += test_vector(
    "",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709"
  );

  /* WebSocket handshake test case */
  /* Key: "dGhlIHNhbXBsZSBub25jZQ==" + GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" */
  /* Expected: "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" (base64 of SHA1) */
  char const * ws_test = "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  uchar hash[20];
  at_sha1_hash( (uchar const *)ws_test, strlen(ws_test), hash );
  print_hash( "WebSocket test", hash );

  if( failures == 0 ) {
    printf( "\nAll tests passed!\n" );
    return 0;
  } else {
    printf( "\n%d tests failed!\n", failures );
    return 1;
  }
}
