#include <stdio.h>
#include <openssl/rsa.h>
#include "rsa.h"

// https://gist.github.com/irbull/08339ddcd5686f509e9826964b17bb59
int main(int argc, char *argv[])
{
    RSA *rsa = generate_rsa_keypair(2048);
    char *public_key = get_public_key_pem(rsa);
    char *private_key = get_private_key_pem(rsa);
    RSA *p_rsa = load_rsa_private_key_from_pem(private_key);
    RSA *pb_rsa = load_rsa_public_key_from_pem(public_key);
    printf("%s\n", public_key);
    printf("%s\n", private_key);
    printf("%d\n", p_rsa != NULL);
    printf("%d\n", pb_rsa != NULL);

    RSA_free(rsa);
    RSA_free(p_rsa);
    RSA_free(pb_rsa);
    free(public_key);
    free(private_key);
    return 0;
}