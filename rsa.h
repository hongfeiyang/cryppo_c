#include <stdbool.h>
#include <assert.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>

typedef unsigned char byte;

int RSA_generate_keypair(EVP_PKEY **skey, EVP_PKEY **vkey);
char *get_public_key_pem(RSA *rsa);
char *get_private_key_pem(RSA *rsa);
RSA *load_rsa_private_key_from_pem(char *pem);
RSA *load_rsa_public_key_from_pem(char *pem);
int RSA_Verify(const byte *msg, size_t mlen, const byte *sig, size_t slen, EVP_PKEY *pkey);
int RSA_Sign(const byte *msg, size_t mlen, byte **sig, size_t *slen, EVP_PKEY *pkey);
void RSA_Sig_print(const char* label, const byte* buff, size_t len);
