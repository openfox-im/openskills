/* at_aes_ref.c was imported from the OpenSSL project circa 2023-Aug.
   Original source files:  crypto/evp/e_aes.c crypto/modes/gcm128.c */

#include "at_aes_gcm.h"
#include "at/infra/at_util.h"

#include <assert.h>

#define at_gcm_init  at_gcm_init_4bit
#define at_gcm_gmult at_gcm_gmult_4bit
#define at_gcm_ghash at_gcm_ghash_4bit

static void
at_aes_gcm_setiv( at_aes_gcm_ref_t * gcm,
                  uchar const        iv[ 12 ] ) {

  uint ctr;
  gcm->len.u[ 0 ] = 0;  /* AAD length */
  gcm->len.u[ 1 ] = 0;  /* Message length */
  gcm->ares = 0;
  gcm->mres = 0;

  at_memcpy( gcm->Yi.c, iv, 12 );
  gcm->Yi.c[12] = 0;
  gcm->Yi.c[13] = 0;
  gcm->Yi.c[14] = 0;
  gcm->Yi.c[15] = 1;
  ctr = 1;

  gcm->Xi.u[0] = 0;
  gcm->Xi.u[1] = 0;

  at_aes_encrypt( gcm->Yi.c, gcm->EK0.c, &gcm->key );
  ctr++;

  gcm->Yi.d[3] = at_uint_bswap( ctr );
}

void
at_aes_128_gcm_init_ref( at_aes_gcm_ref_t * gcm,
                         uchar const        key[ 16 ],
                         uchar const        iv[ 12 ] ) {

  at_memset( gcm, 0, sizeof(at_aes_gcm_ref_t) );

  at_aes_key_ref_t * ks = &gcm->key;
  at_aes_set_encrypt_key( key, 128, ks );

  at_aes_encrypt( gcm->H.c, gcm->H.c, ks );
  gcm->H.u[ 0 ] = at_ulong_bswap( gcm->H.u[ 0 ] );
  gcm->H.u[ 1 ] = at_ulong_bswap( gcm->H.u[ 1 ] );

  at_gcm_init( gcm->Htable, gcm->H.u );
  at_aes_gcm_setiv( gcm, iv );
}

void
at_aes_256_gcm_init_ref( at_aes_gcm_ref_t * gcm,
                         uchar const        key[ 32 ],
                         uchar const        iv[ 12 ] ) {

  at_memset( gcm, 0, sizeof(at_aes_gcm_ref_t) );

  at_aes_key_ref_t * ks = &gcm->key;
  at_aes_set_encrypt_key( key, 256, ks );

  at_aes_encrypt( gcm->H.c, gcm->H.c, ks );
  gcm->H.u[ 0 ] = at_ulong_bswap( gcm->H.u[ 0 ] );
  gcm->H.u[ 1 ] = at_ulong_bswap( gcm->H.u[ 1 ] );

  at_gcm_init( gcm->Htable, gcm->H.u );
  at_aes_gcm_setiv( gcm, iv );
}

static int
at_gcm128_aad( at_aes_gcm_ref_t * aes_gcm,
               uchar const *      aad,
               ulong              aad_sz ) {

  ulong alen = aes_gcm->len.u[ 0 ];

  if( AT_UNLIKELY( aes_gcm->len.u[ 1 ] ) )
    return -2;

  alen += aad_sz;
  if (alen > (1UL<<61) || (sizeof(aad_sz) == 8 && alen < aad_sz))
    return -1;
  aes_gcm->len.u[0] = alen;

  uint n = aes_gcm->ares;
  if (n) {
    while (n && aad_sz) {
      aes_gcm->Xi.c[n] ^= *(aad++);
      --aad_sz;
      n = (n + 1) % 16;
    }
    if (n == 0)
      at_gcm_gmult( aes_gcm->Xi.u, aes_gcm->Htable );
    else {
      aes_gcm->ares = n;
      return 0;
    }
  }
  ulong i;
  if ((i = (aad_sz & (ulong)-16))) {
    at_gcm_ghash( aes_gcm->Xi.u, aes_gcm->Htable, aad, i );
    aad += i;
    aad_sz -= i;
  }
  if (aad_sz) {
    n = (unsigned int)aad_sz;
    for (i = 0; i < aad_sz; ++i)
      aes_gcm->Xi.c[i] ^= aad[i];
  }

  aes_gcm->ares = n;
  return 0;
}

/* TODO separate reference code and GCM128 */

static int
at_gcm128_encrypt( at_aes_gcm_ref_t * ctx,
                   uchar const *      in,
                   uchar *            out,
                   ulong              len ) {

  uint n, ctr, mres;
  ulong i;
  ulong mlen = ctx->len.u[1];
  void *key = &ctx->key;

  mlen += len;
  if (mlen > ((1UL<<36) - 32) || (sizeof(len) == 8 && mlen < len))
    return -1;
  ctx->len.u[1] = mlen;

  mres = ctx->mres;

  if (ctx->ares) {
    /* First call to encrypt finalizes GHASH(AAD) */
    if (len == 0) {
      at_gcm_gmult( ctx->Xi.u, ctx->Htable );
      ctx->ares = 0;
      return 0;
    }
    at_memcpy(ctx->Xn, ctx->Xi.c, sizeof(ctx->Xi));
    ctx->Xi.u[0] = 0;
    ctx->Xi.u[1] = 0;
    mres = sizeof(ctx->Xi);
    ctx->ares = 0;
  }

  ctr = at_uint_bswap( ctx->Yi.d[3] );

  n = mres % 16;
  for (i = 0; i < len; ++i) {
    if (n == 0) {
      at_aes_encrypt( ctx->Yi.c, ctx->EKi.c, key );
      ++ctr;
      ctx->Yi.d[3] = at_uint_bswap( ctr );
    }
    ctx->Xn[mres++] = out[i] = in[i] ^ ctx->EKi.c[n];
    n = (n + 1) % 16;
    if (mres == sizeof(ctx->Xn)) {
      at_gcm_ghash( ctx->Xi.u, ctx->Htable, ctx->Xn, sizeof(ctx->Xn) );
      mres = 0;
    }
  }

  ctx->mres = mres;
  return 0;
}

static int
at_gcm128_decrypt( at_aes_gcm_ref_t * ctx,
                   uchar const *      in,
                   uchar *            out,
                   ulong              len ) {

  uint n, ctr, mres;
  ulong i;
  ulong mlen = ctx->len.u[1];
  void * key = &ctx->key;

  mlen += len;
  if (mlen > ((1UL<<36) - 32) || (sizeof(len) == 8 && mlen < len))
    return -1;
  ctx->len.u[1] = mlen;

  mres = ctx->mres;

  if (ctx->ares) {
    /* First call to decrypt finalizes GHASH(AAD) */
    if (len == 0) {
      at_gcm_gmult( ctx->Xi.u, ctx->Htable );
      ctx->ares = 0;
      return 0;
    }
    at_memcpy(ctx->Xn, ctx->Xi.c, sizeof(ctx->Xi));
    ctx->Xi.u[0] = 0;
    ctx->Xi.u[1] = 0;
    mres = sizeof(ctx->Xi);
    ctx->ares = 0;
  }

  ctr = at_uint_bswap( ctx->Yi.d[3] );

  n = mres % 16;
  for (i = 0; i < len; ++i) {
    uchar c;
    if (n == 0) {
      at_aes_encrypt( ctx->Yi.c, ctx->EKi.c, key );
      ++ctr;
      ctx->Yi.d[3] = at_uint_bswap( ctr );
    }
    out[i] = (ctx->Xn[mres++] = c = in[i]) ^ ctx->EKi.c[n];
    n = (n + 1) % 16;
    if (mres == sizeof(ctx->Xn)) {
      at_gcm_ghash( ctx->Xi.u, ctx->Htable, ctx->Xn, sizeof(ctx->Xn) );
      mres = 0;
    }
  }

  ctx->mres = mres;
  return 0;
}

static void
at_gcm128_finish( at_aes_gcm_ref_t * ctx ) {

  ulong alen = ctx->len.u[0] << 3;  // 176
  ulong clen = ctx->len.u[1] << 3;  // 9296

  struct {
    ulong hi;
    ulong lo;
  } bitlen;
  uint mres = ctx->mres;

  if( mres ) {
    uint blocks = (mres + 15u) & 0xfffffff0u; // 16

    at_memset(ctx->Xn + mres, 0, blocks - mres);
    mres = blocks;
    if (mres == sizeof(ctx->Xn)) {
      at_gcm_ghash( ctx->Xi.u, ctx->Htable, ctx->Xn, mres );
      mres = 0;
    }
  } else if( ctx->ares ) {
    at_gcm_gmult( ctx->Xi.u, ctx->Htable );
  }

  alen = at_ulong_bswap( alen );
  clen = at_ulong_bswap( clen );

  bitlen.hi = alen;
  bitlen.lo = clen;
  at_memcpy( ctx->Xn + mres, &bitlen, sizeof(bitlen) );
  mres += (uint)sizeof(bitlen);
  at_gcm_ghash( ctx->Xi.u, ctx->Htable, ctx->Xn, mres );

  ctx->Xi.u[0] ^= ctx->EK0.u[0];
  ctx->Xi.u[1] ^= ctx->EK0.u[1];
}

void
at_aes_gcm_encrypt_ref( at_aes_gcm_ref_t * aes_gcm,
                        uchar *            c,
                        uchar const *      p,
                        ulong              sz,
                        uchar const *      aad,
                        ulong              aad_sz,
                        uchar              tag[ 16 ] ) {

  at_gcm128_aad( aes_gcm, aad, aad_sz );

  ulong bulk = 0UL;
  assert( 0==at_gcm128_encrypt( aes_gcm, p+bulk, c+bulk, sz-bulk ) );

  /* CRYPTO_gcm128_tag */
  at_gcm128_finish( aes_gcm );
  at_memcpy( tag, aes_gcm->Xi.c, 16 );
}

int
at_aes_gcm_decrypt_ref( at_aes_gcm_ref_t * aes_gcm,
                        uchar const *      c,
                        uchar *            p,
                        ulong              sz,
                        uchar const *      aad,
                        ulong              aad_sz,
                        uchar const        tag[ 16 ] ) {

  at_gcm128_aad( aes_gcm, aad, aad_sz );

  ulong bulk = 0UL;
  assert( 0==at_gcm128_decrypt( aes_gcm, c+bulk, p+bulk, sz-bulk ) );

  /* CRYPTO_gcm128_finish */
  at_gcm128_finish( aes_gcm );
  return 0==at_memcmp( aes_gcm->Xi.c, tag, 16 );  /* TODO USE CONSTANT TIME COMPARE */
}