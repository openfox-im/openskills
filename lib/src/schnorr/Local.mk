# Avatar src/crypto/schnorr/Local.mk
# TOS-compatible Schnorr signature implementation

$(call add-hdrs,../at_schnorr.h)
$(call add-objs,at_schnorr,at_crypto)

# Tests
# $(call make-unit-test,test_schnorr,test_schnorr,at_crypto at_util)