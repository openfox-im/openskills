# Avatar src/crypto/base58/Local.mk

$(call add-hdrs,../at_base58.h)
$(call add-objs,at_base58,at_crypto)
# Note: at_base58_tmpl.c is included by at_base58.c

# SIMD equivalence tests
$(call make-unit-test,test_base58_simd,test_base58_simd,at_crypto at_util)
$(call run-unit-test,test_base58_simd,)