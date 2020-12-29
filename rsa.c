#include "rsa.h"

RSA *generate_rsa_keypair(int bits)
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
