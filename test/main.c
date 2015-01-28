#include "../ocb3-ref.h"
#include <stdio.h>
#include <string.h>

static void pbuf(void *p, unsigned len, const void *s){
    unsigned i;
    if (s){
        printf("%s", (char *)s);
    }
    for (i = 0; i < len; i++){
        printf("%02X", (unsigned)(((unsigned char *)p)[i]));
    }
    printf("\n");
}



static void vectors(ae_ctx *ctx, int len, char noncev, char P, char A)
{
    char pt[128];
    char ct[144];
    char nonce[] = {0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x0}; 
    nonce[11] = noncev;
    int i;
    for (i=0; i < 128; i++){
        pt[i] = i;
    }

    i = ae_encrypt(ctx,nonce,pt,P,pt,A,ct,NULL,AE_FINALIZE);
    // printf("P=%d,A=%d: ",P,A); pbuf(ct, i, NULL);
    pbuf(nonce, 12, "N: ");
    pbuf(pt, A, "A: ");
    pbuf(pt, P, "P: ");
    pbuf(ct, i, "C: ");
    printf("\n");
}


void validate_orig(){
    char pt[1024];
    char ct[1024];
    char tag[16];
    char nonce[12] = {0,};
    char key[32] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
    ae_ctx ctx;
    char *val_buf, *next;
    int i, len;


    if (1) {
		ae_init(&ctx, key, 16, 12, 16);
		/* pbuf(&ctx, sizeof(ctx), "CTX: "); */
		vectors(&ctx,0 ,0, 0, 0);
		vectors(&ctx,8, 1, 8, 8);
		vectors(&ctx,8, 2, 0, 8);
		vectors(&ctx,8, 3, 8, 0);
		vectors(&ctx,8, 4, 16, 16);
		vectors(&ctx,8, 5, 0, 16);
		vectors(&ctx,8, 6, 16, 0);
		vectors(&ctx,8, 7, 24, 24);
		vectors(&ctx,8, 8, 0, 24);
		vectors(&ctx,8, 9, 24, 0);
		vectors(&ctx,8, 10, 32, 32);
		vectors(&ctx,8, 11, 0, 32);
		vectors(&ctx,8, 12, 32, 0);
		vectors(&ctx,8, 13, 40, 40);
		vectors(&ctx,8, 14, 0, 40);
		vectors(&ctx,8, 15, 40, 0);
    }


    /*
     K = zeros(KEYLEN-8) || num2str(TAGLEN,8)
      C = <empty string>
      for i = 0 to 127 do
         S = zeros(8i)
         N = num2str(3i+1,96)
         C = C || OCB-ENCRYPT(K,N,S,S)
         N = num2str(3i+2,96)
         C = C || OCB-ENCRYPT(K,N,<empty string>,S)
         N = num2str(3i+3,96)
         C = C || OCB-ENCRYPT(K,N,S,<empty string>)
      end for
      N = num2str(385,96)
      Output : OCB-ENCRYPT(K,N,C,<empty string>)

   Iteration i of the loop adds 2i + (3 * TAGLEN / 8) bytes to C,
   resulting in an ultimate length for C of 22,400 bytes when TAGLEN ==
   128, 20,864 bytes when TAGLEN == 192, and 19,328 bytes when TAGLEN ==
   64.  The final OCB-ENCRYPT has an empty plaintext component, so
   serves only to authenticate C.  The output should be:

     AEAD_AES_128_OCB_TAGLEN128 Output: 67E944D23256C5E0B6C61FA22FDF1EA2
    */
    
    val_buf = (char *) malloc(22400+16);
    next = val_buf;
    uint16_t enc_len;
    
    memset(key,0, 32);
    memset(pt,0, 128);
    memset(nonce,0,12);
    key[OCB_KEY_LEN-1] = OCB_TAG_LEN*8;
    ae_init(&ctx, key, OCB_KEY_LEN, 12, OCB_TAG_LEN);


    /* RFC Vector test */
    for (i = 0; i < 128; i++) {
        nonce[11] = (3*i+1);
        nonce[10] = ((3*i+1)) >> 8;
        enc_len = ae_encrypt(&ctx,nonce,pt,i,pt,i,ct,NULL,AE_FINALIZE);
        memcpy(next, ct, enc_len);
        next = next+enc_len;

        nonce[11] = (3*i+2);
        nonce[10] = ((3*i+2)) >> 8;
        enc_len = ae_encrypt(&ctx,nonce,pt,i,pt,0,ct,NULL,AE_FINALIZE);
        memcpy(next, ct, enc_len);
        next = next+enc_len;

        nonce[11] = (3*i+3);
        nonce[10] = ((3*i+3)) >> 8;
        enc_len = ae_encrypt(&ctx,nonce,pt,0,pt,i,ct,NULL,AE_FINALIZE);
        memcpy(next, ct, enc_len);
        next = next+enc_len;

    }
    nonce[11] = (385) & 0xFF;
    nonce[10] = ((385)>> 8) ;
    ae_encrypt(&ctx,nonce,NULL,0,val_buf,next-val_buf,ct,tag,AE_FINALIZE);
    printf("AEAD_AES_%d_OCB_TAGLEN%d Output:", OCB_KEY_LEN*8,OCB_TAG_LEN*8 );
    pbuf(tag,OCB_TAG_LEN,0);
}

int main(){
    validate_orig(); // check RFC7253 test vectors
}