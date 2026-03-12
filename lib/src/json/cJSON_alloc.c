#include "at/crypto/json/cJSON_alloc.h"
#include "at/crypto/json/cJSON.h"
#include "at/infra/at_util_base.h"

#include <stddef.h>

static ulong g_initialized;
static AT_TL at_alloc_t * g_cjson_alloc_ctx;

static void *
cjson_alloc( size_t sz ) {
  return at_alloc_malloc( g_cjson_alloc_ctx, alignof(max_align_t), (ulong)sz );
}

static void
cjson_free( void * ptr ) {
  at_alloc_free( g_cjson_alloc_ctx, ptr );
}

void
cJSON_alloc_install( at_alloc_t * alloc ) {
  g_cjson_alloc_ctx = alloc;

  if( AT_ATOMIC_CAS( &g_initialized, 0UL, 1UL )==0UL ) {
    cJSON_Hooks hooks = {
      .malloc_fn = cjson_alloc,
      .free_fn   = cjson_free,
    };
    cJSON_InitHooks( &hooks );
  } else {
    while( g_initialized!=1UL ) AT_SPIN_PAUSE();
  }
}