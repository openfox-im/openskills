/* ChaCha20 SIMD Equivalence Tests
   Tests that SIMD implementations produce identical results to reference.
   Test vectors from ~/avatar/src/tck/test_vectors/chacha20.yaml */

#include "at/crypto/at_chacha.h"
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
  char const * key_hex;
  char const * nonce_hex;
  char const * plaintext_hex;
  ulong        plaintext_length;
  char const * ciphertext_hex;
} test_vector_t;

/* Test vectors from src/tck/test_vectors/chacha20.yaml */
static test_vector_t const test_vectors[] = {
  { "rfc8439_test",
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "000000000000004a00000000",
    "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
    114,
    "e3647a29ded31528ef56bac70f7a7ac3b735c7444da42d99823ef9938c8ebfdcf05bb71a822c62981aa1ea608f47933f2ed755b62d9312ae72037674f3e93e244c2328d32f75bcc15bb7574fde0c6fcdf87b7aa25b5972970c2ae6cced86a10be9496fc61c407dfdc01510ed8f4eb35d0d62" },
  { "empty_plaintext",
    "4242424242424242424242424242424242424242424242424242424242424242",
    "000000000000000000000000",
    "",
    0,
    "" },
  { "single_byte",
    "4242424242424242424242424242424242424242424242424242424242424242",
    "000000000000000000000000",
    "ab",
    1,
    "0f" },
  { "one_block",
    "0101010101010101010101010101010101010101010101010101010101010101",
    "020202020202020202020202",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    64,
    "06e1f8d66ac5c75181f3e5ed9fa16aa909a1fb57a4a9b0110c84fcdc0d710880072a4342af88dec0138daf141a3f471c01e77c1fda90999496d601a36a8c0412" },
  { "two_blocks",
    "0101010101010101010101010101010101010101010101010101010101010101",
    "020202020202020202020202",
    "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    128,
    "06e1f8d66ac5c75181f3e5ed9fa16aa909a1fb57a4a9b0110c84fcdc0d710880072a4342af88dec0138daf141a3f471c01e77c1fda90999496d601a36a8c0412e61cf22e8da3e8da712de9f9d38be4298cb36c0d83aa7dd314841bbdf59644dcd313f9f53b0e06b9d6cb3f0788ce2ee78993d9d27a3edf0a52589cbb698519d5" },
  { "one_block_plus_one",
    "0101010101010101010101010101010101010101010101010101010101010101",
    "020202020202020202020202",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    65,
    "f91e0729953a38ae7e0c1a12605e9556f65e04a85b564feef37b0323f28ef77ff8d5bcbd5077213fec7250ebe5c0b8e3fe1883e0256f666b6929fe5c9573fbed19" },
  { "zero_key_nonce",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "000000000000000000000000",
    "48656c6c6f2c20776f726c6421",
    13,
    "3edd8cc1cfdd1de72f2f068172" },
};

#define TEST_VECTOR_CNT (sizeof(test_vectors)/sizeof(test_vectors[0]))

/* Test encryption matches expected ciphertext */
static int
test_encrypt( test_vector_t const * tv ) {
  uchar key[32];
  uchar nonce[12];
  uchar plaintext[256];
  uchar expected_ct[256];
  uchar ciphertext[256];

  hex_to_bytes( tv->key_hex, key, 32 );
  hex_to_bytes( tv->nonce_hex, nonce, 12 );
  int pt_sz = hex_to_bytes( tv->plaintext_hex, plaintext, sizeof(plaintext) );
  if( pt_sz < 0 ) pt_sz = 0;
  hex_to_bytes( tv->ciphertext_hex, expected_ct, sizeof(expected_ct) );

  /* Initialize and encrypt */
  at_chacha20_ctx_t ctx[1];
  at_chacha20_init( ctx, key, nonce, 0 ); /* counter=0 */
  at_chacha20_crypt( ctx, ciphertext, plaintext, (ulong)pt_sz );

  if( at_memcmp( ciphertext, expected_ct, (ulong)pt_sz ) != 0 ) {
    printf( "FAIL: encrypt_%s\n", tv->name );
    printf( "  Expected: " );
    print_hex( expected_ct, (ulong)pt_sz );
    printf( "\n  Got:      " );
    print_hex( ciphertext, (ulong)pt_sz );
    printf( "\n" );
    return 1;
  }

  printf( "PASS: encrypt_%s\n", tv->name );
  return 0;
}

/* Test decryption matches original plaintext */
static int
test_decrypt( test_vector_t const * tv ) {
  uchar key[32];
  uchar nonce[12];
  uchar plaintext[256];
  uchar ciphertext[256];
  uchar decrypted[256];

  hex_to_bytes( tv->key_hex, key, 32 );
  hex_to_bytes( tv->nonce_hex, nonce, 12 );
  int pt_sz = hex_to_bytes( tv->plaintext_hex, plaintext, sizeof(plaintext) );
  if( pt_sz < 0 ) pt_sz = 0;
  hex_to_bytes( tv->ciphertext_hex, ciphertext, sizeof(ciphertext) );

  /* Initialize and decrypt */
  at_chacha20_ctx_t ctx[1];
  at_chacha20_init( ctx, key, nonce, 0 ); /* counter=0 */
  at_chacha20_crypt( ctx, decrypted, ciphertext, (ulong)pt_sz );

  if( at_memcmp( decrypted, plaintext, (ulong)pt_sz ) != 0 ) {
    printf( "FAIL: decrypt_%s\n", tv->name );
    printf( "  Expected: " );
    print_hex( plaintext, (ulong)pt_sz );
    printf( "\n  Got:      " );
    print_hex( decrypted, (ulong)pt_sz );
    printf( "\n" );
    return 1;
  }

  printf( "PASS: decrypt_%s\n", tv->name );
  return 0;
}

/* Test encrypt->decrypt roundtrip */
static int
test_roundtrip( test_vector_t const * tv ) {
  uchar key[32];
  uchar nonce[12];
  uchar original[256];
  uchar encrypted[256];
  uchar decrypted[256];

  hex_to_bytes( tv->key_hex, key, 32 );
  hex_to_bytes( tv->nonce_hex, nonce, 12 );
  int pt_sz = hex_to_bytes( tv->plaintext_hex, original, sizeof(original) );
  if( pt_sz < 0 ) pt_sz = 0;

  /* Skip empty plaintext */
  if( pt_sz == 0 ) {
    printf( "PASS: roundtrip_%s (empty)\n", tv->name );
    return 0;
  }

  at_chacha20_ctx_t ctx[1];

  /* Encrypt */
  at_chacha20_init( ctx, key, nonce, 0 );
  at_chacha20_crypt( ctx, encrypted, original, (ulong)pt_sz );

  /* Decrypt */
  at_chacha20_init( ctx, key, nonce, 0 );
  at_chacha20_crypt( ctx, decrypted, encrypted, (ulong)pt_sz );

  if( at_memcmp( decrypted, original, (ulong)pt_sz ) != 0 ) {
    printf( "FAIL: roundtrip_%s\n", tv->name );
    printf( "  Original:   " );
    print_hex( original, (ulong)pt_sz );
    printf( "\n  After RT:   " );
    print_hex( decrypted, (ulong)pt_sz );
    printf( "\n" );
    return 1;
  }

  printf( "PASS: roundtrip_%s\n", tv->name );
  return 0;
}

/* Test consistency of multiple encryptions with same key/nonce */
static int
test_consistency( void ) {
  int fail = 0;

  uchar key[32];
  uchar nonce[12];
  at_memset( key, 0x42, 32 );
  at_memset( nonce, 0x00, 12 );

  uchar plaintext[128];
  at_memset( plaintext, 0xAB, 128 );

  uchar ct1[128];
  uchar ct2[128];

  at_chacha20_ctx_t ctx[1];

  /* First encryption */
  at_chacha20_init( ctx, key, nonce, 0 );
  at_chacha20_crypt( ctx, ct1, plaintext, 128 );

  /* Second encryption */
  at_chacha20_init( ctx, key, nonce, 0 );
  at_chacha20_crypt( ctx, ct2, plaintext, 128 );

  if( at_memcmp( ct1, ct2, 128 ) != 0 ) {
    printf( "FAIL: consistency\n" );
    fail++;
  } else {
    printf( "PASS: consistency\n" );
  }

  return fail;
}

/* Test keystream generation consistency */
static int
test_keystream_consistency( void ) {
  int fail = 0;

  uchar key[32];
  uchar nonce[12];
  at_memset( key, 0x42, 32 );
  at_memset( nonce, 0x00, 12 );

  uchar zeros[256];
  uchar ks1[256];
  uchar ks2[256];

  at_memset( zeros, 0, 256 );

  at_chacha20_ctx_t ctx[1];

  /* Generate keystream by encrypting zeros */
  at_chacha20_init( ctx, key, nonce, 0 );
  at_chacha20_crypt( ctx, ks1, zeros, 256 );

  at_chacha20_init( ctx, key, nonce, 0 );
  at_chacha20_crypt( ctx, ks2, zeros, 256 );

  if( at_memcmp( ks1, ks2, 256 ) != 0 ) {
    printf( "FAIL: keystream_consistency\n" );
    fail++;
  } else {
    printf( "PASS: keystream_consistency\n" );
  }

  return fail;
}

/* Test various sizes (exercises different SIMD paths) */
static int
test_various_sizes( void ) {
  int fail = 0;

  uchar key[32];
  uchar nonce[12];
  at_memset( key, 0x42, 32 );
  at_memset( nonce, 0x00, 12 );

  ulong sizes[] = { 1, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256 };

  for( ulong s = 0; s < sizeof(sizes)/sizeof(sizes[0]); s++ ) {
    ulong sz = sizes[s];

    uchar original[512];
    uchar encrypted[512];
    uchar decrypted[512];
    at_memset( original, (uchar)(0x30 + (s % 10)), sz );

    at_chacha20_ctx_t ctx[1];

    /* Encrypt */
    at_chacha20_init( ctx, key, nonce, 0 );
    at_chacha20_crypt( ctx, encrypted, original, sz );

    /* Decrypt */
    at_chacha20_init( ctx, key, nonce, 0 );
    at_chacha20_crypt( ctx, decrypted, encrypted, sz );

    if( at_memcmp( decrypted, original, sz ) != 0 ) {
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

  printf( "=== ChaCha20 Encryption Tests ===\n" );
  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    fail += test_encrypt( &test_vectors[i] );
  }

  printf( "\n=== ChaCha20 Decryption Tests ===\n" );
  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    fail += test_decrypt( &test_vectors[i] );
  }

  printf( "\n=== ChaCha20 Roundtrip Tests ===\n" );
  for( ulong i = 0; i < TEST_VECTOR_CNT; i++ ) {
    fail += test_roundtrip( &test_vectors[i] );
  }

  printf( "\n=== ChaCha20 Consistency Tests ===\n" );
  fail += test_consistency();
  fail += test_keystream_consistency();

  printf( "\n=== ChaCha20 Various Sizes Tests ===\n" );
  fail += test_various_sizes();

  printf( "\n%d tests, %d failures\n",
          (int)(TEST_VECTOR_CNT * 3 + 2 + 12), fail );
  printf( "%s\n", fail ? "SOME TESTS FAILED" : "ALL TESTS PASSED" );

  return fail;
}
