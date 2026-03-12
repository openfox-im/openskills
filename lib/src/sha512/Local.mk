# Avatar src/crypto/sha512/Local.mk

$(call add-hdrs,../at_sha512.h)
$(call add-objs,at_sha512,at_crypto)

# x86 AVX2 optimized implementation
ifdef AT_HAS_AVX
$(call add-asms,at_sha512_core_avx2,at_crypto)
endif

ifdef AT_HAS_AVX
$(call add-objs,at_sha512_batch_avx,at_crypto)
endif
ifdef AT_HAS_AVX512
$(call add-objs,at_sha512_batch_avx512,at_crypto)
endif