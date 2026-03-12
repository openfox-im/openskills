#include <at/crypto/at_address.h>
#include <stdio.h>

static int g_pass = 0;
static int g_fail = 0;

#define TEST_ASSERT( cond, msg ) do {                                \
  if( !(cond) ) {                                                    \
    printf( "FAIL: %s:%d: %s\n", __func__, __LINE__, msg );         \
    g_fail++;                                                        \
    return;                                                          \
  }                                                                  \
} while(0)

#define TEST_PASS() do { g_pass++; printf( "PASS: %s\n", __func__ ); } while(0)

static void
test_normal_roundtrip( void ) {
  uchar pubkey[32];
  for( ulong i = 0; i < 32UL; i++ ) pubkey[i] = (uchar)i;

  at_address_t a;
  TEST_ASSERT( at_address_new_normal( &a, 1, pubkey ) == 0, "new normal" );
  TEST_ASSERT( at_address_is_normal( &a ) == 1, "is normal" );
  TEST_ASSERT( at_address_is_mainnet( &a ) == 1, "is mainnet" );

  char s[128];
  TEST_ASSERT( at_address_as_string( &a, s, sizeof(s) ) == 0, "as_string" );

  at_address_t b;
  TEST_ASSERT( at_address_from_string( s, &b ) == 0, "from_string" );
  TEST_ASSERT( b.addr_type == AT_ADDRESS_TYPE_NORMAL, "decoded type normal" );
  TEST_ASSERT( b.integrated_data_sz == 0UL, "no integrated data" );
  TEST_ASSERT( at_memcmp( b.public_key, pubkey, 32UL ) == 0, "pubkey roundtrip" );

  TEST_PASS();
}

static void
test_integrated_roundtrip( void ) {
  uchar pubkey[32];
  for( ulong i = 0; i < 32UL; i++ ) pubkey[i] = (uchar)(31UL - i);

  uchar payload[6] = { 1, 2, 3, 4, 5, 6 };

  at_address_t a;
  TEST_ASSERT( at_address_new_data( &a, 0, pubkey, payload, sizeof(payload) ) == 0, "new data" );
  TEST_ASSERT( at_address_is_normal( &a ) == 0, "not normal" );
  TEST_ASSERT( at_address_is_mainnet( &a ) == 0, "is testnet" );

  char s[256];
  TEST_ASSERT( at_address_as_string( &a, s, sizeof(s) ) == 0, "as_string data" );

  at_address_t b;
  TEST_ASSERT( at_address_from_string( s, &b ) == 0, "from_string data" );
  TEST_ASSERT( b.addr_type == AT_ADDRESS_TYPE_DATA, "decoded type data" );
  TEST_ASSERT( b.integrated_data_sz == sizeof(payload), "decoded data size" );
  TEST_ASSERT( at_memcmp( b.integrated_data, payload, sizeof(payload) ) == 0, "decoded data bytes" );

  TEST_PASS();
}

static void
test_extract_data_only( void ) {
  uchar pubkey[32] = {0};
  uchar payload[4] = { 9, 8, 7, 6 };
  at_address_t a;
  TEST_ASSERT( at_address_new_data( &a, 1, pubkey, payload, sizeof(payload) ) == 0, "new data" );

  uchar out[16];
  ulong out_sz = sizeof(out);
  int had = 0;
  TEST_ASSERT( at_address_extract_data_only( &a, out, &out_sz, &had ) == 0, "extract data" );
  TEST_ASSERT( had == 1, "had data" );
  TEST_ASSERT( out_sz == sizeof(payload), "output size" );
  TEST_ASSERT( at_memcmp( out, payload, sizeof(payload) ) == 0, "output bytes" );
  TEST_ASSERT( a.addr_type == AT_ADDRESS_TYPE_NORMAL, "address now normal" );
  TEST_ASSERT( a.integrated_data_sz == 0UL, "address data cleared" );

  TEST_PASS();
}

static void
test_extract_data_copy_and_split( void ) {
  uchar pubkey[32];
  for( ulong i = 0; i < 32UL; i++ ) pubkey[i] = (uchar)(i + 17UL);
  uchar payload[5] = { 11, 22, 33, 44, 55 };

  at_address_t a;
  TEST_ASSERT( at_address_new_data( &a, 1, pubkey, payload, sizeof(payload) ) == 0, "new data" );

  at_address_t no_data;
  uchar out[16];
  ulong out_sz = sizeof(out);
  int has_data = 0;
  TEST_ASSERT( at_address_extract_data( &a, out, &out_sz, &has_data, &no_data ) == 0, "extract_data" );
  TEST_ASSERT( has_data == 1, "extract_data has data" );
  TEST_ASSERT( out_sz == sizeof(payload), "extract_data out size" );
  TEST_ASSERT( at_memcmp( out, payload, sizeof(payload) ) == 0, "extract_data payload" );
  TEST_ASSERT( no_data.addr_type == AT_ADDRESS_TYPE_NORMAL, "extract_data normalized type" );
  TEST_ASSERT( no_data.integrated_data_sz == 0UL, "extract_data normalized size" );
  TEST_ASSERT( a.addr_type == AT_ADDRESS_TYPE_DATA, "extract_data does not mutate source" );

  at_address_t b;
  TEST_ASSERT( at_address_new_data( &b, 0, pubkey, payload, sizeof(payload) ) == 0, "new data for split" );
  uchar split_pub[32];
  at_address_type_t split_ty = AT_ADDRESS_TYPE_NORMAL;
  uchar split_out[16];
  ulong split_out_sz = sizeof(split_out);
  TEST_ASSERT( at_address_split( &b, split_pub, &split_ty, split_out, &split_out_sz ) == 0, "split" );
  TEST_ASSERT( split_ty == AT_ADDRESS_TYPE_DATA, "split type" );
  TEST_ASSERT( split_out_sz == sizeof(payload), "split size" );
  TEST_ASSERT( at_memcmp( split_out, payload, sizeof(payload) ) == 0, "split payload" );
  TEST_ASSERT( at_memcmp( split_pub, pubkey, 32UL ) == 0, "split pubkey" );
  TEST_ASSERT( b.addr_type == AT_ADDRESS_TYPE_NORMAL, "split mutates to normal" );

  TEST_PASS();
}

int
main( void ) {
  printf( "=== Address Tests ===\n" );
  test_normal_roundtrip();
  test_integrated_roundtrip();
  test_extract_data_only();
  test_extract_data_copy_and_split();
  printf( "=== Results: %d/%d passed ===\n", g_pass, g_pass + g_fail );
  return g_fail ? 1 : 0;
}
