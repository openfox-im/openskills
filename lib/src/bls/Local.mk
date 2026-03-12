# Avatar src/crypto/bls/Local.mk
# BLS12-381 wrapper (uses vendored blst)

$(call add-hdrs,../at_bls12_381.h)
$(call add-objs,at_bls12_381,at_crypto)
