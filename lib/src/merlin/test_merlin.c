/* Merlin transcript tests

   Test vectors from: https://github.com/zkcrypto/merlin/blob/3.0.0/src/strobe.rs */

#include <at/crypto/at_merlin.h>
#include <at/infra/at_yaml.h>
#include <stdio.h>
#include <string.h>

static void
print_hex( uchar const * data, ulong sz ) {
  for( ulong i = 0; i < sz; i++ ) {
    printf( "%02x", data[ i ] );
  }
}

static int
test_equivalence_simple( void ) {
  at_merlin_transcript_t t[1];
  uchar challenge[ 32 ];
  uchar expected [ 32 ];

  at_merlin_transcript_init( t, AT_MERLIN_LITERAL("test protocol") );
  at_merlin_transcript_append_message( t, AT_MERLIN_LITERAL("some label"), (uchar *)AT_MERLIN_LITERAL("some data") );
  at_merlin_transcript_challenge_bytes( t, AT_MERLIN_LITERAL("challenge"), challenge, 32 );

  /* Expected from Rust merlin crate test vectors */
  at_yaml_hex_to_bytes( expected, 32, "d5a21972d0d5fe320c0d263fac7fffb8145aa640af6e9bca177c03c7efcf0615" );

  if( at_memcmp( challenge, expected, 32 ) != 0 ) {
    printf( "FAIL: merlin_simple\n" );
    printf( "  Expected: " ); print_hex( expected, 32 ); printf( "\n" );
    printf( "  Got:      " ); print_hex( challenge, 32 ); printf( "\n" );
    return 1;
  }

  printf( "PASS: merlin_simple\n" );
  return 0;
}

static int
test_multiple_messages( void ) {
  at_merlin_transcript_t t[1];
  uchar challenge1[ 32 ];
  uchar challenge2[ 32 ];

  at_merlin_transcript_init( t, AT_MERLIN_LITERAL("test") );
  at_merlin_transcript_append_message( t, AT_MERLIN_LITERAL("msg1"), (uchar *)"hello", 5 );
  at_merlin_transcript_challenge_bytes( t, AT_MERLIN_LITERAL("c1"), challenge1, 32 );
  at_merlin_transcript_append_message( t, AT_MERLIN_LITERAL("msg2"), (uchar *)"world", 5 );
  at_merlin_transcript_challenge_bytes( t, AT_MERLIN_LITERAL("c2"), challenge2, 32 );

  /* Challenges should be different */
  if( at_memcmp( challenge1, challenge2, 32 ) == 0 ) {
    printf( "FAIL: merlin_multiple (challenges should differ)\n" );
    return 1;
  }

  printf( "PASS: merlin_multiple\n" );
  return 0;
}

static int
test_append_u64( void ) {
  at_merlin_transcript_t t1[1];
  at_merlin_transcript_t t2[1];
  uchar challenge1[ 32 ];
  uchar challenge2[ 32 ];

  /* Using append_u64 */
  at_merlin_transcript_init( t1, AT_MERLIN_LITERAL("test") );
  at_merlin_transcript_append_u64( t1, AT_MERLIN_LITERAL("value"), 0x123456789ABCDEF0UL );
  at_merlin_transcript_challenge_bytes( t1, AT_MERLIN_LITERAL("c"), challenge1, 32 );

  /* Using append_message with raw bytes */
  at_merlin_transcript_init( t2, AT_MERLIN_LITERAL("test") );
  ulong value = 0x123456789ABCDEF0UL;
  at_merlin_transcript_append_message( t2, AT_MERLIN_LITERAL("value"), (uchar *)&value, 8 );
  at_merlin_transcript_challenge_bytes( t2, AT_MERLIN_LITERAL("c"), challenge2, 32 );

  /* Should be identical */
  if( at_memcmp( challenge1, challenge2, 32 ) != 0 ) {
    printf( "FAIL: merlin_append_u64\n" );
    printf( "  u64:     " ); print_hex( challenge1, 32 ); printf( "\n" );
    printf( "  message: " ); print_hex( challenge2, 32 ); printf( "\n" );
    return 1;
  }

  printf( "PASS: merlin_append_u64\n" );
  return 0;
}

int main( void ) {
  int fail = 0;

  printf( "=== Merlin Transcript Tests ===\n" );
  fail += test_equivalence_simple();
  fail += test_multiple_messages();
  fail += test_append_u64();

  printf( "\n%d failures\n", fail );
  printf( "%s\n", fail ? "SOME TESTS FAILED" : "ALL TESTS PASSED" );
  return fail;
}