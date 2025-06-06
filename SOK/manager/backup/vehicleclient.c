#include<stdio.h>
#include<time.h>
#include<string.h>
#include"include/miracl.h"
#include<arpa/inet.h>
#include<unistd.h>
#include<stdlib.h>
#include<hiredis/hiredis.h>

#define HOST "127.0.0.1"
#define PORT 12346
#define P "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
#define A "0000000000000000000000000000000000000000000000000000000000000000"
#define B "0000000000000000000000000000000000000000000000000000000000000007"
#define G_X "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
#define G_Y "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
#define N "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

void gen_priv_key(miracl* mip, big sk, big q);
void register_vehicle();


void register_vehicle(miracl* mip)
{
    mip->IOBASE = 16;
    big sk = mirvar(0);
    big q = mirvar(0);
    big a = mirvar(0);
    big b = mirvar(0);
    epoint* p = epoint_init();
    epoint* pk = epoint_init();
    unsigned char pk_raw_bytes[64];
    memset(pk_raw_bytes, 0, 64);
    unsigned char cid[32];
    unsigned char apk_as_bytes[128];

    int sock;
    struct sockaddr_in server_addr;

    // Create a socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, HOST, &server_addr.sin_addr) <= 0) {
        perror("Invalid address or address not supported");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection to the server failed");
        close(sock);
        exit(EXIT_FAILURE);
    }


    // Send the 64-byte string
    

    // Close the socket


    cinstr(a, A);
    cinstr(b, B);
    cinstr(q, P);
    ecurve_init(a,b,q,MR_PROJECTIVE);
    cinstr(a, G_X);
    cinstr(b, G_Y);
    epoint_set(a,b,1,p);
    cinstr(q, N);                    //curve initialisation and generator point initialisation
    
    gen_priv_key(mip, sk, q);
    cotnum(sk,stdout);
    ecurve_mult(sk, p, pk);         //generate private key and calculate public key

    epoint_get(pk, a, b);
    big_to_bytes(32, a, pk_raw_bytes, TRUE);
    big_to_bytes(32, b, pk_raw_bytes + 32, TRUE);  //checked correct points

    

    if (send(sock, pk_raw_bytes, 64, 0) < 0) {
        perror("Failed to send data");
    } else {
        printf("64-byte string sent to the server successfully.\n");
    }

    printf("\npk_x: ");
    for(int i = 0; i < 32; i++)
        printf("%02x",pk_raw_bytes[i]);
    printf("\npk_y: ");
    for(int i = 0; i < 32; i++)
        printf("%02x",(pk_raw_bytes+32)[i]);
    
    recv(sock, cid, 32, 0);

    printf("\nhash: ");
    for(int i = 0; i < 32; i++)
        printf("%02x",cid[i]);


    redisContext *context = redisConnect("127.0.0.1", 6379);
    if (context == NULL || context->err) {
        if (context) {
            printf("Connection error: %s\n", context->errstr);
            redisFree(context);
        } else {
            printf("Connection error: cannot allocate redis context\n");
        }
        exit(1);
    }
    const char *argv[] = {"GET", cid};
    size_t argvlen[] = {3, 32};
    redisReply *reply = redisCommandArgv(context, 2, argv, argvlen);
    if (reply == NULL) {
        printf("GET command failed\n");
        redisFree(context);
        exit(0);
    }

    if (reply->type == REDIS_REPLY_STRING) {
        memcpy(apk_as_bytes, reply->str, 128);

    } else {
        printf("Key not found or error occurred\n");
    }
    freeReplyObject(reply);
    redisFree(context);


    printf("\nc1_x: ");
    for(int i = 0; i < 32; i++)
        printf("%02x",apk_as_bytes[i]);
    printf("\nc1_y: ");
    for(int i = 0; i < 32; i++)
        printf("%02x",(apk_as_bytes+32)[i]);
    printf("\nc2_x: ");
    for(int i = 0; i < 32; i++)
        printf("%02x",(apk_as_bytes+64)[i]);
    printf("\nc2_y: ");
    for(int i = 0; i < 32; i++)
        printf("%02x",(apk_as_bytes+96)[i]);


    //write to apk.keys
    FILE* f = fopen("../vehicle/apk.key","wb");
    char sk_str[32];
    big_to_bytes(32, sk, sk_str, TRUE);
    fwrite(sk_str,32,1,f);
    fwrite(apk_as_bytes,128,1,f);
    fwrite(cid,32, 1, f);

    fclose(f);
    //written to apk.keys
    close(sock);
    epoint_free(p);
    epoint_free(pk);
    mirkill(sk);
    mirkill(q);
    mirkill(a);
    mirkill(b);
}

void gen_priv_key(miracl* mip, big sk, big q)
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

int main()
{
    miracl* mip = mirsys(256,50);
    register_vehicle(mip);
    mirexit();
}