#include<stdio.h>
#include"miracl.h"

int main(int argc, char* argv[])
{
    miracl* mip = mirsys(50,256);
    mip->IOBASE = 16;
    char* sk = "489d945c50807336b05a645ce8f05e856e7ce3ae1c6eb9798b4ba84c9062d61e";
    char* c1_x = "7e95df4e1d78d4c918378833f355e1f5833f36a0dfdf30d37869aa4719a8af77";
    char* c1_y = "bf8bcddb027fa54811b02731e0b90244bc430846cdb231784896d54fb3167b8a";
    char* c2_x = "906252cbfd9de0bb8a4864b2fd65e65c12c91bdf2bda6ae5472ea9d0306d7a45";
    char* c2_y = "d992ec9ab036fc5cf2157e44b1cfb8b0d695e96ba17b437483132891d270ef55";

    unsigned char x[32];
    unsigned char y[32];

    big a = mirvar(0);
    big b = mirvar(0);
    FILE* f = fopen("apk.key","wb");

    cinstr(a,sk);
    big_to_bytes(32, a, x, TRUE);
    fwrite(x,32,1,f);

    cinstr(a,c1_x);
    cinstr(b,c1_y);
    
    big_to_bytes(32,a,x,TRUE);
    big_to_bytes(32,b,y,TRUE);
    fwrite(x,32,1,f);
    fwrite(y,32,1,f);

    cinstr(a,c2_x);
    cinstr(b,c2_y);
    
    big_to_bytes(32,a,x,TRUE);
    big_to_bytes(32,b,y,TRUE);
    fwrite(x,32,1,f);
    fwrite(y,32,1,f);

    fclose(f);
    f = fopen("apk.key","rb");
    fread(x,32, 1, f);
    fread(y,32, 1, f);


    fclose(f);
}