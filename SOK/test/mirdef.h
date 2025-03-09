/*
 *   MIRACL compiler/hardware definitions - mirdef.h
 */
#define MR_LITTLE_ENDIAN
#define MIRACL 32
#define mr_utype int
#define MR_IBITS 32
#define MR_LBITS 64
#define mr_unsign32 unsigned int
#define mr_unsign64 unsigned long
#define mr_dltype long
#define MR_DLTYPE_IS_LONG
#define MR_NOASM
#define MR_ALWAYS_BINARY
#define MAXBASE ((mr_small)1<<(MIRACL-1))
#define MR_KCM 4
#define MR_BITSINCHAR 8
#define MR_SMALL_AES
#define MR_EDWARDS
#define MR_NO_LAZY_REDUCTION
#define MR_NO_RAND
#define MR_NOKOBLITZ
#define MR_NO_SS
