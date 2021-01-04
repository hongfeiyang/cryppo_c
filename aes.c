#include "aes.h"

int gcm_encrypt(byte *plaintext, int plaintext_len,
                byte *aad, int aad_len,
                byte *key,
                byte *iv, int iv_len,
                byte *ciphertext,
                byte *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    do
    {
        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new()))
        {
            printf("EVP_CIPHER_CTX_new failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        /* Initialise the encryption operation. */
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        {
            printf("EVP_EncryptInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        /*
         * Set IV length if default 12 bytes (96 bits) is not appropriate
         */
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        {
            printf("EVP_CIPHER_CTX_ctrl failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        /* Initialise key and IV */
        if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        {
            printf("EVP_EncryptInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        /*
        * Provide any AAD data. This can be called zero or more times as
        * required
        */
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        {
            printf("EVP_EncryptUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        /*
        * Provide the message to be encrypted, and obtain the encrypted output.
        * EVP_EncryptUpdate can be called multiple times if necessary
        */
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        {
            printf("EVP_EncryptUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        ciphertext_len = len;

        /*
        * Finalise the encryption. Normally ciphertext bytes may be written at
        * this stage, but this does not occur in GCM mode
        */
        if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        {
            printf("EVP_EncryptFinal_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        ciphertext_len += len;

        /* Get the tag */
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        {
            printf("EVP_CIPHER_CTX_ctrl failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
    } while (0);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int gcm_decrypt(byte *ciphertext, int ciphertext_len,
                byte *aad, int aad_len,
                byte *tag,
                byte *key,
                byte *iv, int iv_len,
                byte *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    do
    {
        /* Create and initialise the context */
        if (!(ctx = EVP_CIPHER_CTX_new()))
        {
            printf("EVP_CIPHER_CTX_new failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        /* Initialise the decryption operation. */
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        {
            printf("EVP_DecryptInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        {
            printf("EVP_CIPHER_CTX_ctrl failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        /* Initialise key and IV */
        if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        {
            printf("EVP_DecryptInit_ex failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        /*
         * Provide any AAD data. This can be called zero or more times as
         * required
         */
        if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        {
            printf("EVP_DecryptUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        /*
         * Provide the message to be decrypted, and obtain the plaintext output.
         * EVP_DecryptUpdate can be called multiple times if necessary
         */
        if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        {
            printf("EVP_DecryptUpdate failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }
        plaintext_len = len;

        /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        {
            printf("EVP_CIPHER_CTX_ctrl failed, error 0x%lx\n", ERR_get_error());
            break; /* failed */
        }

        /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
        ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    } while (0);

        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}