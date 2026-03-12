#include "at_hmac.h"

#include "at_sha256.h"
#include "at_sha512.h"

#define HASH_ALG      sha256
#define HASH_BLOCK_SZ AT_SHA256_BLOCK_SZ
#define HASH_SZ       AT_SHA256_HASH_SZ
#include "at_hmac_tmpl.c"

#define HASH_ALG      sha384
#define HASH_BLOCK_SZ AT_SHA384_BLOCK_SZ
#define HASH_SZ       AT_SHA384_HASH_SZ
#include "at_hmac_tmpl.c"

#define HASH_ALG      sha512
#define HASH_BLOCK_SZ AT_SHA512_BLOCK_SZ
#define HASH_SZ       AT_SHA512_HASH_SZ
#include "at_hmac_tmpl.c"