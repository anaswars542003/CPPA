#include<string.h>
#include<time.h>
#include"sok.h"


#define a_str  "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
#define b_str  "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"
#define q_str  "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
#define x_str  "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
#define y_str  "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
#define n_str  "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"

void read_keys_init(big sk, char* c, epoint* c1);
size_t read_message(char* msg);

int main(int argc, char* argv[])
{
    miracl* mip = mirsys(100,16);
    mip->IOBASE = 16;

    
    signature_t sig;

    big a = mirvar(0);
    big b = mirvar(0);
    big q = mirvar(0);

    cinstr(a, a_str);
    cinstr(b, b_str);
    cinstr(q, q_str);
    ecurve_init(a,b,q,MR_PROJECTIVE);
    cinstr(a, x_str);
    cinstr(b, y_str);
    epoint* p = epoint_init();
    int n = epoint_set(a,b,1,p);
    cinstr(q, n_str);
    
    

    big sk = mirvar(0);
    epoint* c1 = epoint_init();
    unsigned char c[128];
    
    char msg[200];
    size_t msg_size;
    int t = 0;
    
    //use a file with sk,c1_x,c1_y,c2_x,c2_y stored in continuos byte stream. (read using "rb")
    
    read_keys_init(sk, c, c1);
    msg_size = read_message(msg);
    //recieved APK , sk and message to generate proof
    
    clock_t start;
    clock_t end;

    start = clock();
    for(int i = 0 ; i < 100; i++){
        gen_proof(q, p, sk, c, msg, msg_size, t, sig);
    }
    end = clock();
    double time_taken = (double)(end - start)/CLOCKS_PER_SEC;
    printf("Time for signing 100 messages: %f\n",time_taken);
    printf("Average time : %f\n", time_taken/100);
    

    
    start = clock();
    for(int i = 0 ; i < 100; i++){
        n = verify_proof(q, p, c, msg, msg_size, t, sig);
    }
    end = clock();
    time_taken = (double)(end - start)/CLOCKS_PER_SEC;
    printf("Time for signing 100 messages: %f\n",time_taken);
    printf("Average time : %f\n", time_taken/100);
    
    n ? printf("TRUE") : printf("FALSE");

    printf("\n\nsignature: ");
    for(int i = 0; i < 96; i++){
        printf("%02x",(unsigned char)sig[i]);
    }
    
    printf("\n\n");
   
    
    //printf("%f\n",cpu_time_used);
    epoint_free(c1);
   //epoint_free(c2);
    epoint_free(p);
    mirkill(sk);
    mirkill(a);
    mirkill(b);
    mirkill(q);
    mirexit();
    return 0;
}

void read_keys_init(big sk, char* c, epoint* c1)
{
    big a = mirvar(0);
    big b = mirvar(0);
    FILE* f = fopen("apk.key","rb");
    fread(c, 32, 1, f);
    bytes_to_big(32, c, sk);
    fread(c, 32, 4, f);
    bytes_to_big(32, c, a);
    bytes_to_big(32, c+32, b);
    int n = epoint_set(a,b,0,c1);


    fclose(f);
    mirkill(a);
    mirkill(b);
}

size_t read_message(char* msg)
{
    char a[] = "HELLO WORLDASDWASDAANJJ";
    strcpy(msg, a);
    return sizeof(a);
}
