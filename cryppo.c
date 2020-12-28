#include <stdio.h>
#include <stdbool.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

RSA *generate_keypair(int bits)
{
    int ret = 0;
    BIGNUM *bn = NULL;
    RSA *rsa = NULL;

    bn = BN_new();
    ret = BN_set_word(bn, RSA_F4);
    if (ret != 1)
    {
        goto err;
    }

    rsa = RSA_new();
    ret = RSA_generate_key_ex(rsa, bits, bn, NULL);
    if (ret != 1)
    {
        goto err;
    }
    BN_free(bn);
    return rsa;

err:
    BN_free(bn);
    RSA_free(rsa);
    return NULL;
}

static char *bio_to_string(BIO *bio)
{
    int len = BIO_pending(bio);
    char *pem = malloc(len + 1);
    if (BIO_read(bio, pem, len) != len)
    {
        free(pem);
        return NULL;
    }
    pem[len] = '\0';
    return pem;
}

char *get_public_key_pem(RSA *rsa)
{

    BIO *bio = NULL;
    bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_RSAPublicKey(bio, rsa) != 1)
    {
        goto err;
    }
    char *pem = bio_to_string(bio);
    if (pem == NULL)
    {
        goto err;
    }
    BIO_free_all(bio);
    return pem;
err:
    BIO_free_all(bio);
    return NULL;
}

char *get_private_key_pem(RSA *rsa)
{

    BIO *bio = NULL;
    bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL) != 1)
    {
        goto err;
    }
    char *pem = bio_to_string(bio);
    if (pem == NULL)
    {
        goto err;
    }
    BIO_free_all(bio);
    return pem;
err:
    BIO_free_all(bio);
    return NULL;
}

// pem must be null byte terminated
RSA *load_rsa_private_key_from_pem(char *pem)
{
    BIO *bio = NULL;
    RSA *rsa = NULL;

    bio = BIO_new_mem_buf((void *)pem, -1);
    if (bio == NULL)
    {
        return NULL;
    }
    rsa = PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL);
    if (rsa == NULL)
    {
        char buffer[120];
        ERR_error_string(ERR_get_error(), buffer);
        printf("Error reading key:%s\n", buffer);
    }
    BIO_free_all(bio);
    return rsa;
}

// pem must be null byte terminated
RSA *load_rsa_public_key_from_pem(char *pem)
{
    BIO *bio = NULL;
    RSA *rsa = NULL;

    bio = BIO_new_mem_buf((void *)pem, -1);
    if (bio == NULL)
    {
        return NULL;
    }
    rsa = PEM_read_bio_RSAPublicKey(bio, &rsa, NULL, NULL);
    if (rsa == NULL)
    {
        char buffer[120];
        ERR_error_string(ERR_get_error(), buffer);
        printf("Error reading key:%s\n", buffer);
    }
    BIO_free_all(bio);
    return rsa;
}

// https://gist.github.com/irbull/08339ddcd5686f509e9826964b17bb59
int main(int argc, char *argv[])
{
    RSA *rsa = generate_keypair(2048);
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