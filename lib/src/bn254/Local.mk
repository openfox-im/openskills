# Avatar src/crypto/bn254/Local.mk
# Unity build: at_bn254.c includes all other .c files internally

$(call add-hdrs,../at_bn254.h ../at_bn254_internal.h ../at_bn254_scalar.h ../at_poseidon.h)
$(call add-objs,at_bn254,at_crypto)
# Unity build: at_poseidon.c includes at_poseidon_params.c
$(call add-objs,at_poseidon,at_crypto)