#include "at_chacha_rng.h"
#include "at/infra/at_util.h"

AT_FN_CONST ulong
at_chacha_rng_align( void ) {
  return alignof(at_chacha_rng_t);
}

AT_FN_CONST ulong
at_chacha_rng_footprint( void ) {
  return sizeof(at_chacha_rng_t);
}

void *
at_chacha_rng_new( void * shmem, int mode ) {
  if( AT_UNLIKELY( !shmem ) ) {
    AT_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }
  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)shmem, alignof(at_chacha_rng_t) ) ) ) {
    AT_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }
  at_memset( shmem, 0, sizeof(at_chacha_rng_t) );
  if( AT_UNLIKELY( (mode!=AT_CHACHA_RNG_MODE_MOD) & (mode!=AT_CHACHA_RNG_MODE_SHIFT) ) ) {
    AT_LOG_WARNING(( "invalid mode" ));
    return NULL;
  }
  ((at_chacha_rng_t *)shmem)->mode = mode;
  ((at_chacha_rng_t *)shmem)->algo = AT_CHACHA_RNG_ALGO_CHACHA20;
  return shmem;
}

at_chacha_rng_t *
at_chacha_rng_join( void * shrng ) {
  if( AT_UNLIKELY( !shrng ) ) {
    AT_LOG_WARNING(( "NULL shrng" ));
    return NULL;
  }
  return (at_chacha_rng_t *)shrng;
}

void *
at_chacha_rng_leave( at_chacha_rng_t * rng ) {
  if( AT_UNLIKELY( !rng ) ) {
    AT_LOG_WARNING(( "NULL rng" ));
    return NULL;
  }
  return (void *)rng;
}

void *
at_chacha_rng_delete( void * shrng ) {
  if( AT_UNLIKELY( !shrng ) ) {
    AT_LOG_WARNING(( "NULL shrng" ));
    return NULL;
  }
  at_memset( shrng, 0, sizeof(at_chacha_rng_t) );
  return shrng;
}

at_chacha_rng_t *
at_chacha_rng_init( at_chacha_rng_t * rng,
                    void const *      key,
                    int               algo ) {
  at_memcpy( rng->key, key, AT_CHACHA_KEY_SZ );
  rng->buf_off  = 0UL;
  rng->buf_fill = 0UL;

  /* invalid algo defaults to chacha20 */
  rng->algo = algo;
  if( algo==AT_CHACHA_RNG_ALGO_CHACHA8 ) {
    at_chacha8_rng_private_refill( rng );
  } else {
    at_chacha20_rng_private_refill( rng );
  }

  return rng;
}

static void
at_chacha_rng_refill_seq( at_chacha_rng_t * rng,
                          void * (* block_fn)( void *, void const *, void const * ) ) {
  ulong fill_target = AT_CHACHA_RNG_BUFSZ - AT_CHACHA_BLOCK_SZ;

  ulong buf_avail;
  while( (buf_avail=(rng->buf_fill - rng->buf_off))<fill_target ) {
    ulong idx = rng->buf_fill >> 6;
    uint idx_nonce[4] __attribute__((aligned(16))) =
      { (uint)idx, 0U, 0U, 0U };
    block_fn( rng->buf + (rng->buf_fill % AT_CHACHA_RNG_BUFSZ),
              rng->key,
              idx_nonce );
    rng->buf_fill += (uint)AT_CHACHA_BLOCK_SZ;
  }
}

void
at_chacha8_rng_refill_seq( at_chacha_rng_t * rng ) {
  at_chacha_rng_refill_seq( rng, at_chacha8_block );
}

void
at_chacha20_rng_refill_seq( at_chacha_rng_t * rng ) {
  at_chacha_rng_refill_seq( rng, at_chacha20_block );
}