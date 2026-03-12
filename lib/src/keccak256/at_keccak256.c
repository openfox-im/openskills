/* Avatar Keccak256 implementation */

#include <at/crypto/at_keccak256.h>
#include <at/crypto/at_keccak256_private.h>

ulong
at_keccak256_align( void ) {
  return AT_KECCAK256_ALIGN;
}

ulong
at_keccak256_footprint( void ) {
  return AT_KECCAK256_FOOTPRINT;
}

void *
at_keccak256_new( void * shmem ) {
  at_keccak256_t * sha = (at_keccak256_t *)shmem;

  if( AT_UNLIKELY( !shmem ) ) {
    AT_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)shmem, at_keccak256_align() ) ) ) {
    AT_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = at_keccak256_footprint();

  at_memset( sha, 0, footprint );

  AT_COMPILER_MFENCE();
  AT_VOLATILE( sha->magic ) = AT_KECCAK256_MAGIC;
  AT_COMPILER_MFENCE();

  return (void *)sha;
}

at_keccak256_t *
at_keccak256_join( void * shsha ) {

  if( AT_UNLIKELY( !shsha ) ) {
    AT_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)shsha, at_keccak256_align() ) ) ) {
    AT_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  at_keccak256_t * sha = (at_keccak256_t *)shsha;

  if( AT_UNLIKELY( sha->magic!=AT_KECCAK256_MAGIC ) ) {
    AT_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return sha;
}

void *
at_keccak256_leave( at_keccak256_t * sha ) {

  if( AT_UNLIKELY( !sha ) ) {
    AT_LOG_WARNING(( "NULL sha" ));
    return NULL;
  }

  return (void *)sha;
}

void *
at_keccak256_delete( void * shsha ) {

  if( AT_UNLIKELY( !shsha ) ) {
    AT_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( AT_UNLIKELY( !at_ulong_is_aligned( (ulong)shsha, at_keccak256_align() ) ) ) {
    AT_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  at_keccak256_t * sha = (at_keccak256_t *)shsha;

  if( AT_UNLIKELY( sha->magic!=AT_KECCAK256_MAGIC ) ) {
    AT_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  AT_COMPILER_MFENCE();
  AT_VOLATILE( sha->magic ) = 0UL;
  AT_COMPILER_MFENCE();

  return (void *)sha;
}

at_keccak256_t *
at_keccak256_init( at_keccak256_t * sha ) {
  at_memset( sha->state, 0, sizeof( sha->state ) );
  
  sha->padding_start = 0;

  return sha;
}

at_keccak256_t *
at_keccak256_append( at_keccak256_t * sha,
                     void const *     _data,
                     ulong            sz ) {

  /* If no data to append, we are done */

  if( AT_UNLIKELY( !sz ) ) return sha; /* optimize for non-trivial append */

  /* Unpack inputs */

  ulong * state         = sha->state;
  uchar * state_bytes   = (uchar*) sha->state;
  ulong   padding_start = sha->padding_start;

  uchar const * data = (uchar const *)_data;

  ulong state_idx = padding_start;
  for( ulong i = 0; i < sz; i++ ) {
    state_bytes[state_idx] ^= data[i];
    state_idx++;
    if( state_idx >= AT_KECCAK256_RATE ) {
      at_keccak256_core(state);
      state_idx = 0;
    }
  }

  sha->padding_start = state_idx;

  return sha;
}

void *
at_keccak256_fini( at_keccak256_t * sha,
                   void *           hash ) {

  /* Unpack inputs */

  ulong * state         = sha->state;
  uchar * state_bytes   = (uchar*) sha->state;
  ulong   padding_start = sha->padding_start;


  /* Append the terminating message byte */

  state_bytes[padding_start] ^= (uchar)0x01;
  state_bytes[AT_KECCAK256_RATE-1] ^= (uchar)0x80;
  at_keccak256_core(state);

  /* Copy the result into hash */

  at_memcpy(hash, state, AT_KECCAK256_OUT_SZ); 
  return hash;
}

void *
at_keccak256_hash( void const * _data,
                ulong        sz,
                void *       _hash ) {
  at_keccak256_t sha;
  at_keccak256_init( &sha );
  at_keccak256_append( &sha, _data, sz );
  at_keccak256_fini( &sha, _hash );


  return _hash;
}

#undef at_keccak256_core