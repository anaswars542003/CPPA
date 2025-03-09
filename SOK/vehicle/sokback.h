#include"miracl.h"
#ifndef SOK_H
#define SOK_H


typedef char signature_t[96];

void cal_e_hash(char* c, char* msg, size_t msg_size, big e);
void gen_proof( big q, epoint* p, big sk, char* c, char* msg,  size_t msg_size, int t, signature_t sig);
BOOL verify_proof( big q, epoint* p, char* c, char* msg, size_t msg_size, int t, signature_t sig);
BOOL batch_verify_proof(big q, epoint* p, int n, char* c[], char* msg[], size_t msg_size[], int t[], signature_t sig[] );

#endif
