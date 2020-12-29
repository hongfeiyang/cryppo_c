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
int sign_it(const byte *msg, size_t mlen, byte **sig, size_t *slen, EVP_PKEY *pkey)
{
    /* Returned to caller */
    int result = -1;

    if (!msg || !mlen || !sig || !pkey)
    {
        assert(0);
        return -1;
    }

    if (*sig)
        OPENSSL_free(*sig);

    *sig = NULL;
    *slen = 0;

    EVP_MD_CTX *ctx = NULL;

    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if (ctx == NULL)
        {
            printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        int rc = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        assert(rc == 1);
        if (rc != 1)
        {
            printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
        assert(rc == 1);
        if (rc != 1)
        {
            printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestSignUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if (rc != 1)
        {
            printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        size_t req = 0;
        rc = EVP_DigestSignFinal(ctx, NULL, &req);
        assert(rc == 1);
        if (rc != 1)
        {
            printf("EVP_DigestSignFinal failed (1), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        assert(req > 0);
        if (!(req > 0))
        {
            printf("EVP_DigestSignFinal failed (2), error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        *sig = OPENSSL_malloc(req);
        assert(*sig != NULL);
        if (*sig == NULL)
        {
            printf("OPENSSL_malloc failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        *slen = req;
        rc = EVP_DigestSignFinal(ctx, *sig, slen);
        assert(rc == 1);
        if (rc != 1)
        {
            printf("EVP_DigestSignFinal failed (3), return code %d, error 0x%lx\n", rc, ERR_get_error());
            break; /* failed */
        }

        assert(req == *slen);
        if (rc != 1)
        {
            printf("EVP_DigestSignFinal failed, mismatched signature sizes %ld, %ld", req, *slen);
            break; /* failed */
        }

        result = 0;

    } while (0);

    if (ctx)
    {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }

    return !!result;
}

int verify_it(const byte *msg, size_t mlen, const byte *sig, size_t slen, EVP_PKEY *pkey)
{
    /* Returned to caller */
    int result = -1;

    if (!msg || !mlen || !sig || !slen || !pkey)
    {
        assert(0);
        return -1;
    }

    EVP_MD_CTX *ctx = NULL;

    do
    {
        ctx = EVP_MD_CTX_create();
        assert(ctx != NULL);
        if (ctx == NULL)
        {
            printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        int rc = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
        assert(rc == 1);
        if (rc != 1)
        {
            printf("EVP_DigestInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey);
        assert(rc == 1);
        if (rc != 1)
        {
            printf("EVP_DigestVerifyInit failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        rc = EVP_DigestVerifyUpdate(ctx, msg, mlen);
        assert(rc == 1);
        if (rc != 1)
        {
            printf("EVP_DigestVerifyUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        /* Clear any errors for the call below */
        ERR_clear_error();

        rc = EVP_DigestVerifyFinal(ctx, sig, slen);
        assert(rc == 1);
        if (rc != 1)
        {
            printf("EVP_DigestVerifyFinal failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        result = 0;

    } while (0);

    if (ctx)
    {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }

    return !!result;
}