# Avatar src/crypto/uno_proofs/Local.mk
# UNO Zero-Knowledge Proof verification

$(call add-hdrs,../at_uno_proofs.h ../at_human_readable_proof.h)
$(call add-objs,at_uno_proofs at_human_readable_proof,at_crypto)
