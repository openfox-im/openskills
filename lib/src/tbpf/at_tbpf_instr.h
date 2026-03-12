#ifndef HEADER_at_ballet_tbpf_at_tbpf_instr_h
#define HEADER_at_ballet_tbpf_at_tbpf_instr_h

/* TBPF instruction encoding/decoding utilities */

#include "at/infra/at_util_base.h"

/* TBPF instruction format (8 bytes):
   - opcode: 8 bits
   - dst: 4 bits
   - src: 4 bits
   - offset: 16 bits (signed)
   - imm: 32 bits (signed) */

union at_tbpf_instr {
  ulong word;  /* Raw 64-bit instruction word */
  struct {
    /* Opcode byte breakdown */
    struct {
      uchar op_class : 3;    /* Operation class */
      uchar op_src   : 1;    /* Source type (K=imm, X=reg) */
      uchar op_mode  : 4;    /* Operation mode/subclass */
    } opcode;
    uchar dst : 4;           /* Destination register */
    uchar src : 4;           /* Source register */
    short offset;            /* 16-bit signed offset */
    int   imm;               /* 32-bit signed immediate */
  } __attribute__((packed));
};

typedef union at_tbpf_instr at_tbpf_instr_t;

AT_STATIC_ASSERT( sizeof(at_tbpf_instr_t)==8UL, tbpf_instr_size );

/* Extract instruction fields from a 64-bit word */

AT_FN_CONST static inline at_tbpf_instr_t
at_tbpf_instr( ulong word ) {
  at_tbpf_instr_t instr;
  instr.word = word;
  return instr;
}

AT_FN_CONST static inline uchar
at_tbpf_instr_opcode( ulong word ) {
  return (uchar)(word & 0xFFUL);
}

AT_FN_CONST static inline uchar
at_tbpf_instr_dst( ulong word ) {
  return (uchar)((word >> 8) & 0x0FUL);
}

AT_FN_CONST static inline uchar
at_tbpf_instr_src( ulong word ) {
  return (uchar)((word >> 12) & 0x0FUL);
}

AT_FN_CONST static inline short
at_tbpf_instr_offset( ulong word ) {
  return (short)((word >> 16) & 0xFFFFUL);
}

AT_FN_CONST static inline int
at_tbpf_instr_imm( ulong word ) {
  return (int)(word >> 32);
}

/* Construct an instruction word from fields */

AT_FN_CONST static inline ulong
at_tbpf_instr_word( uchar opcode,
                    uchar dst,
                    uchar src,
                    short offset,
                    int   imm ) {
  return ((ulong)opcode)
       | (((ulong)dst & 0x0FUL) << 8)
       | (((ulong)src & 0x0FUL) << 12)
       | (((ulong)(ushort)offset) << 16)
       | (((ulong)(uint)imm) << 32);
}

#endif /* HEADER_at_ballet_tbpf_at_tbpf_instr_h */