/* TOS Schnorr signature tests using test vectors from TOS TCK
   Test vectors generated from the same bulletproofs + curve25519-dalek-ng libraries as TOS.
   See: ~/tos/tck/crypto/schnorr.yaml */

#include "at_schnorr.h"
#include <stdio.h>
#include <string.h>

static int
hex_to_bytes( char const * hex, uchar * out, ulong out_sz ) {
  ulong hex_len = at_strlen( hex );
  if( hex_len % 2 != 0 || hex_len / 2 > out_sz ) return -1;
  for( ulong i = 0; i < hex_len / 2; i++ ) {
    unsigned int byte;
    if( sscanf( hex + i * 2, "%02x", &byte ) != 1 ) return -1;
    out[ i ] = (uchar)byte;
  }
  return (int)(hex_len / 2);
}

static void
print_hex( uchar const * data, ulong sz ) {
  for( ulong i = 0; i < sz; i++ ) {
    printf( "%02x", data[ i ] );
  }
}

static int
test_h_generator( void ) {
  /* Test that the H generator constant matches the TCK value */
  char const * expected_hex = "8c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134";
  uchar expected[ 32 ];
  hex_to_bytes( expected_hex, expected, 32 );

  if( at_memcmp( at_schnorr_h_generator, expected, 32 ) != 0 ) {
    printf( "FAIL: h_generator\n" );
    printf( "  Expected: %s\n", expected_hex );
    printf( "  Got:      " );
    print_hex( at_schnorr_h_generator, 32 );
    printf( "\n" );
    return 1;
  }

  printf( "PASS: h_generator\n" );
  return 0;
}

static int
test_public_key_derivation( char const * name,
                            char const * private_key_hex,
                            char const * expected_public_key_hex ) {
  uchar private_key[ 32 ];
  uchar expected_pubkey[ 32 ];
  uchar computed_pubkey[ 32 ];

  hex_to_bytes( private_key_hex, private_key, 32 );
  hex_to_bytes( expected_public_key_hex, expected_pubkey, 32 );

  if( !at_schnorr_public_key_from_private( computed_pubkey, private_key ) ) {
    printf( "FAIL: %s (pubkey derivation failed)\n", name );
    return 1;
  }

  if( at_memcmp( computed_pubkey, expected_pubkey, 32 ) != 0 ) {
    printf( "FAIL: %s (pubkey mismatch)\n", name );
    printf( "  Expected: %s\n", expected_public_key_hex );
    printf( "  Got:      " );
    print_hex( computed_pubkey, 32 );
    printf( "\n" );
    return 1;
  }

  printf( "PASS: %s_pubkey\n", name );
  return 0;
}

static int
test_signature( char const * name,
                char const * private_key_hex,
                char const * public_key_hex,
                char const * message_hex,
                char const * k_hex,
                char const * expected_s_hex,
                char const * expected_e_hex ) {
  uchar private_key[ 32 ];
  uchar public_key[ 32 ];
  uchar message[ 256 ];
  uchar k[ 32 ];
  uchar expected_s[ 32 ];
  uchar expected_e[ 32 ];
  int message_sz;

  hex_to_bytes( private_key_hex, private_key, 32 );
  hex_to_bytes( public_key_hex, public_key, 32 );
  message_sz = hex_to_bytes( message_hex, message, 256 );
  if( message_sz < 0 ) message_sz = 0;
  hex_to_bytes( k_hex, k, 32 );
  hex_to_bytes( expected_s_hex, expected_s, 32 );
  hex_to_bytes( expected_e_hex, expected_e, 32 );

  at_schnorr_signature_t sig[ 1 ];

  /* Test signing */
  if( !at_schnorr_sign_deterministic( sig, private_key, public_key,
                                      message, (ulong)message_sz, k ) ) {
    printf( "FAIL: %s_sign (signing failed)\n", name );
    return 1;
  }

  if( at_memcmp( sig->s, expected_s, 32 ) != 0 ) {
    printf( "FAIL: %s_sign (s mismatch)\n", name );
    printf( "  Expected s: %s\n", expected_s_hex );
    printf( "  Got s:      " );
    print_hex( sig->s, 32 );
    printf( "\n" );
    return 1;
  }

  if( at_memcmp( sig->e, expected_e, 32 ) != 0 ) {
    printf( "FAIL: %s_sign (e mismatch)\n", name );
    printf( "  Expected e: %s\n", expected_e_hex );
    printf( "  Got e:      " );
    print_hex( sig->e, 32 );
    printf( "\n" );
    return 1;
  }

  printf( "PASS: %s_sign\n", name );

  /* Test verification */
  if( !at_schnorr_verify( sig, public_key, message, (ulong)message_sz ) ) {
    printf( "FAIL: %s_verify (verification failed)\n", name );
    return 1;
  }

  printf( "PASS: %s_verify\n", name );

  /* Test that invalid signature fails verification */
  at_schnorr_signature_t bad_sig[ 1 ];
  at_memcpy( bad_sig, sig, sizeof( at_schnorr_signature_t ) );
  bad_sig->e[ 0 ] ^= 0x01; /* Flip a bit */

  if( at_schnorr_verify( bad_sig, public_key, message, (ulong)message_sz ) ) {
    printf( "FAIL: %s_verify_invalid (should have rejected bad signature)\n", name );
    return 1;
  }

  printf( "PASS: %s_verify_invalid\n", name );

  return 0;
}

int main( void ) {
  int fail = 0;

  /* Test H generator matches TCK */
  fail += test_h_generator();

  /* Test vectors from ~/tos/tck/crypto/schnorr.yaml */

  /* Test 1: hello_world */
  fail += test_public_key_derivation(
    "hello_world",
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00",
    "3cc4fec02e2342dca15352d5c5c27135f9e42c5805c07ca9dc500e000f89a665" );

  fail += test_signature(
    "hello_world",
    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00",
    "3cc4fec02e2342dca15352d5c5c27135f9e42c5805c07ca9dc500e000f89a665",
    "48656c6c6f2c20776f726c6421",
    "aabbccddeeff001122334455667788990123456789abcdeffedcba9876543200",
    "52a03c91dcc0b45925a506a60b864fccedeca9c13170f15e74eb43dc21c0920a",
    "7a0c2b0dd4435dd898ab8d74a5b6d1e1614bbfb133259488db0923039190280c" );

  /* Test 2: empty_message */
  fail += test_public_key_derivation(
    "empty_message",
    "1111111111111111111111111111111111111111111111111111111111111101",
    "1685f8ba5b0c7265ef6f4d75f6a95429b3672383fa4fee7b0878b0b182243249" );

  fail += test_signature(
    "empty_message",
    "1111111111111111111111111111111111111111111111111111111111111101",
    "1685f8ba5b0c7265ef6f4d75f6a95429b3672383fa4fee7b0878b0b182243249",
    "",
    "2222222222222222222222222222222222222222222222222222222222222202",
    "2f8eb2515bfbfa5baf1f0bc71a4974f8c41294c2f725e2871c2ac493eee7540c",
    "851ee1caca73832263090db38c5d9928fdea736c3f33bc15b95772eb15ca3101" );

  /* Test 3: 64_bytes_0x55 */
  fail += test_public_key_derivation(
    "64_bytes_0x55",
    "3333333333333333333333333333333333333333333333333333333333333303",
    "4e14f8485d7c884b67c86122651af1f83cdfe9f765587211399c587bf272be62" );

  fail += test_signature(
    "64_bytes_0x55",
    "3333333333333333333333333333333333333333333333333333333333333303",
    "4e14f8485d7c884b67c86122651af1f83cdfe9f765587211399c587bf272be62",
    "55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555",
    "4444444444444444444444444444444444444444444444444444444444444404",
    "6595b6d11da2c681541dbec53213b3eaf5071e63d35892de7235335ddd2c2709",
    "894e22976d527659e84b9eabd52e37f9a0ee981572a68a19bc67fb44053e2c0b" );

  /* Test 4: 32_zeros */
  fail += test_public_key_derivation(
    "32_zeros",
    "7777777777777777777777777777777777777777777777777777777777777707",
    "e062c0b70de48f2213f62590b30481e8beacd141bdf0d6fda1637b018abf5942" );

  fail += test_signature(
    "32_zeros",
    "7777777777777777777777777777777777777777777777777777777777777707",
    "e062c0b70de48f2213f62590b30481e8beacd141bdf0d6fda1637b018abf5942",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "8888888888888888888888888888888888888888888888888888888888888808",
    "c61d2149a4b4b03ec2cc38b6b5b3acc1e881da7c9d3c863c4a97f728b6fd380d",
    "5022bdb8277dbbd3b1a3c9c16befd95e2581c6cbfa8996424e7740478dda1203" );

  printf( "\n%d test groups, %d failures\n", 5, fail );
  printf( "%s\n", fail ? "SOME TESTS FAILED" : "ALL TESTS PASSED" );
  return fail;
}