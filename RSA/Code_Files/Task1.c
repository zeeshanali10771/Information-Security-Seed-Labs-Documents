#include <stdio.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char*msg, BIGNUM*a)
{
   /*Use BN_bn2hex(a) for hex string*
   Use BN_bn2dec(a) for decimal string*/
   char*number_str = BN_bn2hex(a);
   printf("%s %s\n", msg,number_str);
   OPENSSL_free(number_str);
}
void computer_privatekey()
{
   BN_CTX *ctx = BN_CTX_new();
   BIGNUM *p = BN_new();
   BIGNUM *q = BN_new();
   BIGNUM *e = BN_new();
   BN_hex2bn(&p,"F7E75FDC469067FFDC4E847C51F452DF");
   BN_hex2bn(&q,"E85CED54AF57E53E092113E62F436F4F");
   BN_hex2bn(&e,"0D88C3");
   BIGNUM *n = BN_new();
   
   BN_mul(n, p, q, ctx);
   printBN("n= p*q = ", n);
   
   BIGNUM *totient = BN_new();
   BIGNUM *p_minus_one = BN_new();
   BIGNUM *q_minus_one = BN_new();
   
   BIGNUM *one = BN_new();
   BN_hex2bn(&one,"1");
   
   BN_sub(p_minus_one,p,one);
   BN_sub(q_minus_one,q,one);
   
   BN_mul(totient, p_minus_one, q_minus_one, ctx);
   printBN("totient=(p-1)*(q-1) =", totient);
   
   BIGNUM *d = BN_new();
   
   BN_mod_inverse(d, e, totient, ctx);
   printBN("private key d = ", d);
}
int main ()
{
   computer_privatekey();
}
