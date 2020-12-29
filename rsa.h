#include <stdbool.h>
#include <assert.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>

typedef unsigned char byte;

RSA *generate_rsa_keypair(int bits);
char *get_public_key_pem(RSA *rsa);
char *get_private_key_pem(RSA *rsa);
RSA *load_rsa_private_key_from_pem(char *pem);
RSA *load_rsa_public_key_from_pem(char *pem);
