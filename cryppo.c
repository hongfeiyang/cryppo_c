#include <stdio.h>
#include <stdbool.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

bool generate_rsa_keypair(int bits)
{
    size_t pri_len, pub_len;              // Length of private/public key
    char *pri_key = NULL, *pub_key = NULL; // Private/Public key string in PEM

    int ret = 0;
    RSA *rsa = NULL;
    BIGNUM *bn = NULL;
    BIO *bio_public_out = NULL, *bio_private_out = NULL, *bio_public_in = NULL, *bio_private_in = NULL;
    RSA *pb_rsa = NULL, *p_rsa = NULL;
    EVP_PKEY *evp_pbkey = NULL, *evp_pkey = NULL;

    // 1. generate rsa key
    bn = BN_new();
    ret = BN_set_word(bn, RSA_F4);
    if (ret != 1)
    {
        goto free_all;
    }

    rsa = RSA_new();
    ret = RSA_generate_key_ex(rsa, bits, bn, NULL);
    if (ret != 1)
    {
        goto free_all;
    }

    // 2. save public key
    //bio_public_out = BIO_new_file("public.pem", "w+");
    bio_public_out = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_RSAPublicKey(bio_public_out, rsa);
    if (ret != 1)
    {
        goto free_all;
    }

    // 3. save private key
    //bio_private_out = BIO_new_file("private.pem", "w+");
    bio_private_out = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_RSAPrivateKey(bio_private_out, rsa, NULL, NULL, 0, NULL, NULL);

    //4. Get the keys are PEM formatted strings
    pri_len = BIO_pending(bio_private_out);
    pub_len = BIO_pending(bio_public_out);

    pri_key = (char *)malloc(pri_len + 1);
    pub_key = (char *)malloc(pub_len + 1);

    BIO_read(bio_private_out, pri_key, pri_len);
    BIO_read(bio_public_out, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    printf("\n%s\n%s\n", pri_key, pub_key);

    //verify if you are able to re-construct public key
    bio_public_in = BIO_new_mem_buf((void *)pub_key, pub_len);
    if (bio_public_in == NULL)
    {
        return -1;
    }
    pb_rsa = PEM_read_bio_RSAPublicKey(bio_public_in, &pb_rsa, NULL, NULL);
    if (pb_rsa == NULL)
    {
        char buffer[120];
        ERR_error_string(ERR_get_error(), buffer);
        printf("Error reading public key:%s\n", buffer);
    }
    evp_pbkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_pbkey, pb_rsa);

    // verify if you are able to re-construct private key
    bio_private_in = BIO_new_mem_buf((void *)pri_key, pri_len);
    if (bio_private_in == NULL)
    {
        return -1;
    }
    p_rsa = PEM_read_bio_RSAPrivateKey(bio_private_in, &p_rsa, NULL, NULL);
    if (p_rsa == NULL)
    {
        char buffer[120];
        ERR_error_string(ERR_get_error(), buffer);
        printf("Error reading private key:%s\n", buffer);
    }
    evp_pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_pkey, p_rsa);

// 4. free
free_all:
    if (pri_key != NULL)
    {
        free(pri_key);
    }
    if (pub_key != NULL)
    {
        free(pub_key);
    }
    BIO_free_all(bio_public_in);
    BIO_free_all(bio_private_in);
    BIO_free_all(bio_public_out);
    BIO_free_all(bio_private_out);
    EVP_PKEY_free(evp_pkey);
    EVP_PKEY_free(evp_pbkey);
    RSA_free(rsa);
    BN_free(bn);

    return (ret == 1);
}

int main(int argc, char *argv[])
{
    generate_rsa_keypair(2048);
    return 0;
}