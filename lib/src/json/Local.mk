# Avatar src/crypto/json/Local.mk

$(call add-hdrs,include/at/crypto/json/cJSON.h include/at/crypto/json/cJSON_alloc.h)

$(call add-objs,cJSON cJSON_alloc,at_crypto)