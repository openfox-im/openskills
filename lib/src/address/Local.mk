# Avatar src/crypto/address/Local.mk
# TOS-compatible address type helpers (normal + integrated data)

$(call add-hdrs,../at_address.h)
$(call add-objs,at_address,at_crypto)

$(call make-unit-test,test_address,test_address,at_crypto at_util)
$(call run-unit-test,test_address)
