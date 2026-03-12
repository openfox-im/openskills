# Avatar src/crypto/chacha/Local.mk

$(call add-hdrs,../at_chacha.h ../at_chacha_rng.h)
$(call add-objs,at_chacha at_chacha_rng,at_crypto)
ifdef AT_HAS_SSE
$(call add-objs,at_chacha_sse,at_crypto)
endif
ifdef AT_HAS_AVX
$(call add-objs,at_chacha_rng_avx,at_crypto)
endif
ifdef AT_HAS_AVX512
$(call add-objs,at_chacha_rng_avx512,at_crypto)
endif

# SIMD equivalence tests
$(call make-unit-test,test_chacha20_simd,test_chacha20_simd,at_crypto at_util)
$(call run-unit-test,test_chacha20_simd,)