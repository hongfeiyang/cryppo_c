#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
//https://stackoverflow.com/questions/50363097/c-openssl-generate-rsa-keypair-and-read
const char *pcszPassphrase = "open sezamee";

static void gen_callback(int iWhat, int inPrime, void *pParam);
static void init_openssl(void);
static void cleanup_openssl(void);
static int passwd_callback(char *pcszBuff, int size, int rwflag, void *pPass);
static EVP_PKEY *create_rsa_key(RSA *rsa);
static void handle_openssl_error(void);

int main(int argc, char **argv)
{
    size_t pri_len; // Length of private key
    size_t pub_len; // Length of public key
    char *pri_key;  // Private key in PEM
    char *pub_key;  // Public key in PEM

    int ret = 0;
    RSA *r = NULL;
    BIGNUM *bne = NULL;
    BIO *bp_public = NULL, *bp_private = NULL;
    int bits = 2048;
    unsigned long e = RSA_F4;

    RSA *pb_rsa = NULL;
    RSA *p_rsa = NULL;
    EVP_PKEY *evp_pbkey = NULL;
    EVP_PKEY *evp_pkey = NULL;

    BIO *pbkeybio = NULL;
    BIO *pkeybio = NULL;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne, e);
    if (ret != 1)
    {
        goto free_all;
    }

    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if (ret != 1)
    {
        goto free_all;
    }

    // 2. save public key
    //bp_public = BIO_new_file("public.pem", "w+");
    bp_public = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_RSAPublicKey(bp_public, r);
    if (ret != 1)
    {
        goto free_all;
    }

    // 3. save private key
    //bp_private = BIO_new_file("private.pem", "w+");
    bp_private = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

    //4. Get the keys are PEM formatted strings
    pri_len = BIO_pending(bp_private);
    pub_len = BIO_pending(bp_public);

    pri_key = (char *)malloc(pri_len + 1);
    pub_key = (char *)malloc(pub_len + 1);

    BIO_read(bp_private, pri_key, pri_len);
    BIO_read(bp_public, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    printf("\n%s\n%s\n", pri_key, pub_key);

    //verify if you are able to re-construct the keys
    pbkeybio = BIO_new_mem_buf((void *)pub_key, pub_len);
    if (pbkeybio == NULL)
    {
        return -1;
    }
    evp_pbkey = PEM_read_bio_PUBKEY(pbkeybio, &evp_pbkey, NULL, NULL);
    if (evp_pbkey == NULL)
    {
        char buffer[120];
        ERR_error_string(ERR_get_error(), buffer);
        printf("Error reading public key:%s\n", buffer);
    }

    evp_pbkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_pbkey, pb_rsa);
    pkeybio = BIO_new_mem_buf((void *)pri_key, pri_len);
    if (pkeybio == NULL)
    {
        return -1;
    }

    pb_rsa = PEM_read_bio_RSAPublicKey(pbkeybio, &pb_rsa, NULL, NULL);
    if (pb_rsa == NULL)
    {
        char buffer[120];
        ERR_error_string(ERR_get_error(), buffer);
        printf("Error reading public key:%s\n", buffer);
    }

    BIO_free(pbkeybio);
    BIO_free(pkeybio);

// 4. free
free_all:

    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);

    return (ret == 1);
}
