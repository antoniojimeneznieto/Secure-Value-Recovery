/**
 * @file ckvs_crypto.c
 * @headerfile ckvs_crypto.h
 * @brief ckvs_crypto --
 */

#include "ckvs.h"
#include "ckvs_crypto.h"
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <string.h>
#include <assert.h>

#define AUTH_MESSAGE "Auth Key"
#define C1_MESSAGE   "Master Key Encryption"

static int compute_client_keys(ckvs_memrecord_t *mr, unsigned char* user_passphrase) {

    M_REQUIRE_NON_NULL(mr);

    // Compute the stretched key from user passphrase
    M_REQUIRE_NON_NULL(
        SHA256(user_passphrase, strlen(user_passphrase), mr->stretched_key.sha)
    );

    unsigned int size = 0; // used to check if the produced sha is of the correct size
    M_REQUIRE_NON_NULL(
        HMAC(
            EVP_sha256(), mr->stretched_key.sha, SHA256_DIGEST_LENGTH,
            AUTH_MESSAGE, strlen(AUTH_MESSAGE),
            mr->auth_key.sha, &size
        )
    );

    M_REQUIRE(size == SHA256_DIGEST_LENGTH, ERR_INVALID_COMMAND,
              "The authentication key length: '%s' is invalid\n" , size);

    // Repeat the same process to compute the c1 key using C1 message
    M_REQUIRE_NON_NULL(
        HMAC(
            EVP_sha256(),  mr->stretched_key.sha, SHA256_DIGEST_LENGTH,
            C1_MESSAGE, strlen(C1_MESSAGE),
            mr->c1.sha, &size
        )
    );

    M_REQUIRE(size == SHA256_DIGEST_LENGTH, ERR_INVALID_COMMAND, "The C1 key length '%s' is invalid\n", &size);

    return ERR_NONE;
}


int ckvs_client_encrypt_pwd(ckvs_memrecord_t *mr, const char *key, const char *pwd) {

    // NULL pointers checks
    M_REQUIRE_NON_NULL(mr);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);

    // Key has to be <= CKVS_MAXKEYLEN, but PWD can be of any length
    // Key and PWD are null terminated so we can use strlen
    M_REQUIRE(strlen(key) <= CKVS_MAXKEYLEN, ERR_INVALID_ARGUMENT, "Key argument is too big", "");

    // Initialize the memrecord which will hold all the computed keys
    memset(mr, 0, sizeof(ckvs_memrecord_t));

    unsigned char* temp_key = calloc(strlen(key) + strlen(pwd) + 2, sizeof(unsigned char));

    strcpy(temp_key, key);

    // We form the user passphrase by concatenating the key and password as "key|pwd"
    strcat(temp_key, "|");
    strcat(temp_key, pwd);

    temp_key[strlen(key) + strlen(pwd) + 1] = '\0';

    // Compute the authentication key from the stretched key using an authentication message
    error_code code = compute_client_keys(mr, temp_key);

    free(temp_key);

    M_REQUIRE(code == ERR_NONE, code, "Could not compute the encryption keys\n", "");

    return ERR_NONE;
}

int ckvs_client_compute_masterkey(struct ckvs_memrecord *mr, const struct ckvs_sha *c2) {

    // NULL pointer checks
    M_REQUIRE_NON_NULL(mr);
    M_REQUIRE_NON_NULL(c2);

    // Compute the master key ny combining the c1 key from the mr with the given c2 key
    unsigned int size = 0; // used to check if the produced master key is of the correct size
    HMAC(EVP_sha256(),  &mr->c1,            SHA256_DIGEST_LENGTH,
                                 c2->sha,                SHA256_DIGEST_LENGTH,
                                mr->master_key.sha, &size);

    M_REQUIRE(size == SHA256_DIGEST_LENGTH, ERR_INVALID_COMMAND, "The master key length '%s' is invalid\n", size);

    return ERR_NONE;
}


int ckvs_client_crypt_value(const struct ckvs_memrecord *mr, const int do_encrypt,
                            const unsigned char *inbuf, size_t inbuflen,
                            unsigned char *outbuf, size_t *outbuflen )
{
    /* ======================================
     * Implementation adapted from the web:
     *     https://man.openbsd.org/EVP_EncryptInit.3
     * Man page: EVP_EncryptInit
     * Reference:
     *    https://www.coder.work/article/6383682
     * ======================================
     */

    // constant IV -- ok given the entropy in c2
    unsigned char iv[16];
    bzero(iv, 16);

    // Don't set key or IV right away; we want to check lengths
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL, do_encrypt);

    assert(EVP_CIPHER_CTX_key_length(ctx) == 32);
    assert(EVP_CIPHER_CTX_iv_length(ctx)  == 16);

    // Now we can set key and IV
    const unsigned char* const key = (const unsigned char*) mr->master_key.sha;
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    int outlen = 0;
    if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, (int) inbuflen)) {
        // Error
        EVP_CIPHER_CTX_free(ctx);
        return ERR_INVALID_ARGUMENT;
    }

    int tmplen = 0;
    if (!EVP_CipherFinal_ex(ctx, outbuf+outlen, &tmplen)) {
        // Error
        debug_printf("crypt inbuflen %ld outlen %d tmplen %d", inbuflen, outlen, tmplen);
        EVP_CIPHER_CTX_free(ctx);
        return ERR_INVALID_ARGUMENT;
    }

    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);

    *outbuflen = (size_t) outlen;

    return ERR_NONE;
}
