#include<stdio.h>
#include<time.h>
#include<stdlib.h>
#include"sok.h"

void gen_random_number(big sk, big q)
{   
    csprng rng;
    long tod;
    char raw[30] = "09ojnsdj19hsdu213-911wda";
    int rawlen = 30;
    tod = time(NULL);
    strong_init(&rng, rawlen, raw, tod);
    strong_bigrand(&rng, q, sk);
    strong_kill(&rng);
}
 
void cal_e_hash(char* c, char* msg, size_t msg_size, big e)
{   
    char tmp[32];

    sha256 psh;
    shs256_init(&psh);

    for(int i = 0; i < msg_size; i++)
        shs256_process(&psh, c[i]);
    for(int i = 0; i < msg_size; i++)
        shs256_process(&psh, msg[i]);
    shs256_hash(&psh, tmp);
    
    bytes_to_big(32, tmp, e);
    
}

void gen_proof(big q, epoint* p, big sk, char* c, char* msg,  size_t msg_size, int t, signature_t sig)
{
    big r = mirvar(0);
    big e = mirvar(0);  
    big z = mirvar(0); 
    epoint* R = epoint_init();
    epoint* c1 = epoint_init();
    bytes_to_big(32,c,r);
    bytes_to_big(32,c+32,e);
    epoint_set(r,e,0,c1);

    gen_random_number(r, q);

    epoint_copy(c1, R);
    ecurve_add(p,R);
    ecurve_mult(r,R,R);  
    
    //Signature R is set.

    //calculating hash
    cal_e_hash(c, msg,msg_size,e);

    negify(e,e);
    mad(e,sk,r,q,q,z);
    if(exsign(z) == -1)
        add(z,q,z);

    
    epoint_get(R, r, e);
    

    big_to_bytes(32, z, sig, TRUE);
    big_to_bytes(32, r, (sig+32), TRUE);
    big_to_bytes(32, e, (sig+64), TRUE);
                                         // once r is randomised remove this
    mirkill(z);
    epoint_free(c1);
    epoint_free(R);
    mirkill(r); 
    mirkill(e);
}


BOOL verify_proof(big q, epoint* p, char* c, char* msg, size_t msg_size, int t, signature_t sig)
{
    //Ri = zi(C1 + P) + eiC2;
    big z = mirvar(0);
    big e = mirvar(0);
    big r = mirvar(0);
    epoint* R = epoint_init();
    epoint* R_cal = epoint_init();
    epoint* tmp = epoint_init();
    epoint* c1 = epoint_init();
    epoint* c2 = epoint_init();
    
    //set point c1 and c2 from APK c
    bytes_to_big(32, c, e);
    bytes_to_big(32, c+32, r);
    epoint_set(e,r,0,c1);
                                                            //APK c is assumed to be stored in continuos 32 byte locations of char c
    bytes_to_big(32, c+64, e);                                 
    bytes_to_big(32, c+96, r);
    epoint_set(e,r,0,c2);


    //parse signature
    bytes_to_big(32, sig, z);
    bytes_to_big(32, (sig + 32), e);
    bytes_to_big(32, (sig + 64), r);
    epoint_set(e,r,0,R);
      
    //parsed signature R  and z

    //calculate hash
    cal_e_hash(c,msg,msg_size,e);   

    //R_cal = eiC2
    ecurve_mult(e,c2,R_cal);

    //tmp = zi(c1 + P)
    epoint_copy(c1,tmp);
    ecurve_add(p,tmp);
    ecurve_mult(z,tmp,tmp);

    //R_cal = tmp + R_cal
    ecurve_add(tmp,R_cal);

    int n = epoint_comp(R_cal,R);

    epoint_free(R_cal);
    epoint_free(tmp);
    epoint_free(c1);
    epoint_free(c2);
    mirkill(z);
    mirkill(e);
    mirkill(r);
    epoint_free(R);
    return n;
}

BOOL batch_verify_proof(big q, epoint* p, int n, char* c[], char* msg[], size_t msg_size[], int t[], signature_t sig[] )
{
    int vectors[] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
    return TRUE;

}