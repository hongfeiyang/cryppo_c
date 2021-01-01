#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include "rsa.h"
#include <string.h>

// https://gist.github.com/irbull/08339ddcd5686f509e9826964b17bb59
int main(int argc, char *argv[])
{

    // RSA *p_rsa = load_rsa_private_key_from_pem(private_key);
    // RSA *pb_rsa = load_rsa_public_key_from_pem(public_key);
    // printf("%s\n", public_key);
    // printf("%s\n", private_key);
    // printf("%d\n", p_rsa != NULL);
    // printf("%d\n", pb_rsa != NULL);

    // EVP_PKEY *evp_pb_key = EVP_PKEY_new();
    // EVP_PKEY_assign_RSA(evp_pb_key, rsa);

    // EVP_PKEY *evp_p_key = EVP_PKEY_new();
    // EVP_PKEY_assign_RSA(evp_p_key, rsa);

    OpenSSL_add_all_algorithms();

    /* Sign and Verify HMAC keys */
    EVP_PKEY *skey = NULL, *vkey = NULL;

    int rc = RSA_generate_keypair(&skey, &vkey);
    assert(rc == 0);
    if (rc != 0)
        exit(1);

    assert(skey != NULL);
    if (skey == NULL)
        exit(1);

    assert(vkey != NULL);
    if (vkey == NULL)
        exit(1);

    byte msg[] = "TEST TEST TEST";
    byte *sig = NULL;
    size_t slen = 0;

    RSA_Sign(msg, sizeof(msg), &sig, &slen, skey);
    RSA_Sig_print("Signature", sig, slen);
    sig[0] = (byte)1;
    rc = RSA_Verify(msg, sizeof(msg), sig, slen, vkey);
    if (rc == 0)
    {
        printf("Verified signature\n");
    }
    else
    {
        printf("Failed to verify signature, return code %d\n", rc);
    }

    if (sig)
    {
        OPENSSL_free(sig);
    }

    if (skey)
    {
        EVP_PKEY_free(skey);
    }

    if (vkey)
    {
        EVP_PKEY_free(vkey);
    }

    /** You must not call RSA_free() after EVP_PKEY_assgin_RSA() since the ownership of the Key is transferred to EVP_PKEY */
    // RSA_free(rsa);
    // RSA_free(p_rsa);
    // RSA_free(pb_rsa);

    // free(public_key);
    // free(private_key);
    return 0;
}