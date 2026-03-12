# Avatar src/crypto/tos_hash/Local.mk

$(call add-hdrs,../at_tos_hash_v1.h ../at_tos_hash_v2.h ../at_tos_hash_v3.h)
$(call add-objs,at_tos_hash_v1 at_tos_hash_v2 at_tos_hash_v3,at_crypto)

$(call make-unit-test,test_tos_hash_v1,test_tos_hash_v1,at_crypto at_util)
$(call run-unit-test,test_tos_hash_v1,)
$(call make-unit-test,test_tos_hash_v2,test_tos_hash_v2,at_crypto at_util)
$(call run-unit-test,test_tos_hash_v2,)
$(call make-unit-test,test_tos_hash_v3,test_tos_hash_v3,at_crypto at_util)
$(call run-unit-test,test_tos_hash_v3,)
