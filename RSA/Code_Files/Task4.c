#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM *a)
{
   /*Use BN_bn2hex(a) for hex string*
   Use BN_bn2dec(a) for decimal string*/
   char*number_str = BN_bn2hex(a);
   printf("%s %s\n", msg,number_str);
   OPENSSL_free(number_str);
}

int main ()
{
   BN_CTX *ctx = BN_CTX_new();
   BIGNUM *m = BN_new();
   BIGNUM *sign = BN_new();
   //BIGNUM *dec = BN_new();
   BIGNUM *n = BN_new();
   BIGNUM *d = BN_new();
  // BIGNUM *e = BN_new();

   BN_hex2bn(&n,"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5"); 
   BN_hex2bn(&d,"74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
   BN_hex2bn(&m,"49206f776520796f75203030302e");
   //BN_hex2bn(&e,"010001");
   
   //Encryption
   BN_mod_exp(sign, d ,n ,m, ctx);
   printBN("Signed Message= ", sign);
   //Dcryption
   //BN_mod_exp(dec, sign, e, n, ctx);
   //printBN("Decrypted Signed Message= ", dec);
   //printHX(BN_hex2bn(dec));
   
   return 0;
}
