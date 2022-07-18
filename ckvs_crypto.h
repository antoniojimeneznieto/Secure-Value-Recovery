/**
 * @file ckvs_crypto.h
 * @brief client-side cryptographic routines.
 *
 * Defines the format of the primary in-memory data structure used by the client
 */

#pragma once

#include "ckvs_utils.h"

/**
 * @brief Holds the variables necessary to compute a master key
 */
typedef struct ckvs_memrecord {
    ckvs_sha_t stretched_key;   /**< SHA256( key + "|" + pwd ) */
    ckvs_sha_t auth_key;        /**< HMAC-SHA256( key= stretched_key ; "Auth Key" ) */
    ckvs_sha_t c1;              /**< HMAC-SHA256( key= stretched_key ; "Master Key Encryption" ) */
    ckvs_sha_t master_key;      /**< HMAC-SHA256( key= c1 ; c2 ) */
} ckvs_memrecord_t;

/**
 * @brief Generates stretched_key, auth_key and c1 and stores them into the memrecord.
 *
 * @param mr (struct ckvs_memrecord*) the record which will hold the keys
 * @param key (const char*) the key used to compute stretched_key
 * @param pwd (const char*) the password used to compute stretched_key
 * @return int, error code
 */
int ckvs_client_encrypt_pwd(struct ckvs_memrecord *mr, const char *key, const char *pwd);

/**
 * @brief Generates master key from c1 stored in mr and the given c2.
 *
 * @param mr (struct ckvs_memrecord*) the record which will hold master_key. It must contains c1.
 * @param c2 (const struct ckvs_sha*) the value of c2, taken from ckvs_entry
 * @return int, error code
 */
int ckvs_client_compute_masterkey(struct ckvs_memrecord *mr, const struct ckvs_sha *c2);

/**
 * @brief Performs symmetric encryption/decryption using AES256_CBC.
 *
 * @param mr (struct ckvs_memrecord*), must contain the master_key
 * @param do_encrypt (int) 1 for encryption, 0 for decryption
 * @param inbuf (const unsigned char*) byte array to encrypt/decrypt
 * @param inbuflen (size_t) length of inbuf
 * @param outbuf (unsigned char*) byte array of length at least inbuflen+EVP_MAX_BLOCK_LENGTH
 * @param outbuflen (size_t*) actual number of bytes that was written in the output
 * @return int, error code
 */
int ckvs_client_crypt_value(const struct ckvs_memrecord *mr, const int do_encrypt, const unsigned char *inbuf, size_t inbuflen, unsigned char *outbufptr, size_t *outbuflen);
