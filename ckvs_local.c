/**
 * @file ckvs_local.c
 * @headerfile ckvs_local.h
 * @brief ckvs_local -- operations on local databases
 */

#include "ckvs_io.h"
#include "ckvs_utils.h"
#include "ckvs.h"
#include "ckvs_crypto.h"
#include "openssl/evp.h"
#include "ckvs_local.h"
#include "openssl/rand.h"

/**
 * @brief Executes ckvs_client_crypt_value but also manages the potential errors
 *
 * @param mr (struct ckvs_memrecord*), must contain the master_key
 * @param do_encrypt (int) 1 for encryption, 0 for decryption
 * @param inbuf (const unsigned char*) byte array to encrypt/decrypt
 * @param inbuflen (size_t) length of inbuf
 * @param outbuf (unsigned char*) byte array of length at least inbuflen+EVP_MAX_BLOCK_LENGTH
 * @return int, error code
 */

/*
 *  This function could just be merged with ckvs_client_crypt_value and have it manage the release of resources itself.
 */

static int crypt_value(struct CKVS myCKVS, struct ckvs_memrecord mymr, int do_encrypt, unsigned char* inbuf, size_t inbuflen, unsigned char* outbuf) {

    size_t outbuflen = 0;

    error_code code = ckvs_client_crypt_value(&mymr, do_encrypt, inbuf, inbuflen, outbuf, &outbuflen);

    if (code != ERR_NONE) {
        free(inbuf);
        inbuf = NULL;
        free(outbuf);
        outbuf = NULL;
        ckvs_close(&myCKVS);
        M_EXIT(code, "could not decrypt value", "");
    }

    return ERR_NONE;

}

/**
 * @brief Executes the get part of the getset
 *
 * @param myCKVS (struct CKVS) the CKVS database
 * @param mr (struct ckvs_memrecord*), must contain the master_key
 * @param entry_searched (ckvs_entry_t*) the entry to get
 * @return int, an error code
 */

static int do_get(struct CKVS myCKVS, struct ckvs_memrecord mymr, ckvs_entry_t* entry_searched) {

    // Computation of the master key using its c1 and the c2 of the entry found
    error_code code = ckvs_client_compute_masterkey(&mymr, &(entry_searched->c2));

    M_REQUIRE_ELSE_CLOSE_CKVS(code == ERR_NONE, &myCKVS, code, "Unable to compute master key", "");
    size_t size = entry_searched->value_len; // value_len contains the size of the value in the database

    M_REQUIRE_ELSE_CLOSE_CKVS(size != 0, &myCKVS, ERR_NO_VALUE, "No value associated with this key", "");

    unsigned char* inbuf;

    code = read_content(myCKVS.file, entry_searched->value_off, entry_searched->value_len, &inbuf);

    M_REQUIRE_ELSE_CLOSE_CKVS(code == ERR_NONE, &myCKVS ,code, "Unable to read encrypted value", "");

    unsigned char* outbuf = calloc(size + EVP_MAX_BLOCK_LENGTH, sizeof(unsigned char));
    M_REQUIRE_ELSE_RUN_EXIT_CODE(outbuf != NULL,
                                 {
                                     free(inbuf);
                                     inbuf = NULL;
                                     ckvs_close(&myCKVS);
                                 },
                                 ERR_OUT_OF_MEMORY,"Unable to allocate outbuf: Out of memory", "");

    code = crypt_value(myCKVS, mymr, 0, inbuf, size, outbuf);

    M_REQUIRE(code == ERR_NONE, code, "Unable to decrypt the value", "");

    // Print the decrypted value
    pps_printf("%s", outbuf);

    free(inbuf);
    inbuf = NULL;
    free(outbuf);
    outbuf = NULL;

    ckvs_close(&myCKVS);

    return ERR_NONE;
}

/**
 * @brief Executes the set part of the getset
 *
 * @param myCKVS (struct CKVS) the CKVS database
 * @param mr (struct ckvs_memrecord*), must contain the master_key
 * @param entry_searched (ckvs_entry_t*) the entry to get
 * @param set_value (const char*) the value to set
 * @return int, an error code
 */

static int do_set(struct CKVS myCKVS, struct ckvs_memrecord mymr, ckvs_entry_t* entry_searched, const char* set_value) {

    // Our new C2 key initialized to 0
    ckvs_sha_t newc2;
    memset(&newc2, 0, sizeof(ckvs_sha_t)); // Not needed as we set each byte to a random value later

    // We generate a new C2
    M_REQUIRE_ELSE_CLOSE_CKVS(RAND_bytes(newc2.sha, SHA256_DIGEST_LENGTH) == 1, &myCKVS, ERR_IO, "It was impossible to generate a new random C2 key", "");

    // We generate the Master key with the new c2
    error_code code = ckvs_client_compute_masterkey(&mymr, &newc2);

    entry_searched->c2 = newc2;

    M_REQUIRE_ELSE_CLOSE_CKVS(code == ERR_NONE, &myCKVS, code, "Unable to compute new master key", "");

    size_t inbuflen = strlen(set_value) + 1; // + 1 for the null byte \0
    unsigned char* inbuf = calloc(inbuflen, sizeof(unsigned char));


    M_REQUIRE(inbuf != NULL, ERR_OUT_OF_MEMORY, "Unable to allocate inbuf: Out of memory", "");

    memcpy(inbuf, set_value, strlen(set_value));
    inbuf[inbuflen - 1] = '\0';

    size_t outbuflen = 0;
    unsigned char* outbuf = calloc(inbuflen + EVP_MAX_BLOCK_LENGTH, sizeof(unsigned char));

    M_REQUIRE_ELSE_RUN_EXIT_CODE(inbuf != NULL,
                                 {
                                     free(inbuf);
                                     inbuf = NULL;
                                     ckvs_close(&myCKVS);
                                 }
    ,ERR_OUT_OF_MEMORY, "Unable to allocate inbuf: Out of memory", ""
    );

    // We encrypt set_value
    code = ckvs_client_crypt_value(&mymr, 1, inbuf, inbuflen, outbuf, &outbuflen);

    free(inbuf);
    inbuf = NULL;

    M_REQUIRE_ELSE_RUN_EXIT_CODE(code == ERR_NONE,
                                 {
                                     free(outbuf);
                                     outbuf = NULL;
                                     ckvs_close(&myCKVS);
                                 }
    ,code, "could not encrypt value", ""
    );

    code = ckvs_write_encrypted_value(&myCKVS, entry_searched, outbuf, outbuflen);

    free(outbuf);
    outbuf = NULL;
    ckvs_close(&myCKVS);

    M_REQUIRE(code == ERR_NONE, code, "could not write encrypted value", "");

    return ERR_NONE;
}

int ckvs_local_stats(const char *filename, int optargc, char* optargv[]) {
    //Number of arguments checker
    int err_code = nb_arguments_required(&optargc, 0);
    M_REQUIRE(err_code == ERR_NONE, err_code,"Wrong number of arguments", "" );

    // NULL pointer check
    err_code = non_null_checker(filename, optargc, optargv);
    M_REQUIRE(err_code == ERR_NONE, err_code , "NULL pointer exception", "");

    struct CKVS ckvs;
    error_code code = ckvs_open(filename, &ckvs);

    M_REQUIRE_ELSE_CLOSE_CKVS(code == ERR_NONE, &ckvs, code, "could not open file", "");

    print_header(&ckvs.header);

    for(size_t i = 0; i < ckvs.header.table_size ; i++) {
        if(strlen(ckvs.entries[i].key) > 0) print_entry(&ckvs.entries[i]);
    }
    ckvs_close(&ckvs);

    return code;
}

int ckvs_local_getset(const char *filename, const char *key, const char *pwd, const char* set_value) {

    // NULL pointer checks
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(pwd);

    struct CKVS myCKVS;

    // Opening of the database and initialization of myCKVS with the right header and entries
    error_code code = ckvs_open(filename,&myCKVS);

    M_REQUIRE_ELSE_CLOSE_CKVS(code == ERR_NONE, &myCKVS, code, "could not open file", "");

    // Creation of memrecord to store the stretched, auth and c1 keys.
    // It will be initialized in ckvs_client_encrypt_pwd()
    struct ckvs_memrecord mymr;

    // Computation of the stretched, auth and c1 keys
    code = ckvs_client_encrypt_pwd(&mymr, key, pwd);

    M_REQUIRE_ELSE_CLOSE_CKVS(code == ERR_NONE, &myCKVS, code, "could not compute the keys", "");

    // Searching for the key in the entries:
    ckvs_entry_t* entry_searched = 0; // If we can find the entry we will store the address of its pointer here
    code = ckvs_find_entry(&myCKVS, key, &mymr.auth_key, &entry_searched);

    M_REQUIRE_ELSE_CLOSE_CKVS(code == ERR_NONE, &myCKVS, code, "could not find entry\n", "");

    if(set_value == NULL) {
        // Proceed to <get>

        code = do_get(myCKVS, mymr, entry_searched);

        M_REQUIRE(code == ERR_NONE, code, "unable to do get", "");
    }

    else {
        // Proceed to <set>

        code = do_set(myCKVS, mymr, entry_searched, set_value);

        M_REQUIRE(code == ERR_NONE, code, "unable to do set", "");
    }

    return ERR_NONE;

}

int ckvs_local_get(const char *filename,  int optargc, char* optargv[]) {
    //Number of arguments check
    int err_code = nb_arguments_required(&optargc, 2);
    M_REQUIRE(err_code == ERR_NONE, err_code,"Wrong number of arguments", "" );

    // NULL pointer check
    err_code = non_null_checker(filename, optargc, optargv);
    M_REQUIRE(err_code == ERR_NONE, err_code, "NULL pointer exception", "");

    error_code code = ckvs_local_getset(filename, optargv[0], optargv[1], NULL);
    return code;
}


int ckvs_local_set(const char *filename,  int optargc, char* optargv[]) {
    //Number of arguments check
    int err_code = nb_arguments_required(&optargc, 3);
    M_REQUIRE(err_code == ERR_NONE, err_code,"Wrong number of arguments", "" );

    // NULL pointer check
    err_code = non_null_checker(filename, optargc, optargv);
    M_REQUIRE(err_code == ERR_NONE, err_code , "NULL pointer exception", "");

    char* valuefilename = optargv[2];

    size_t buffer_size = 0;
    char* buffer;
    error_code code = read_value_file_content(valuefilename, &buffer, &buffer_size);

    M_REQUIRE(code == ERR_NONE, code, "Unable to read value from file in set", "");

    code = ckvs_local_getset(filename, optargv[0], optargv[1], buffer);
    free(buffer);

    return code;
}

int ckvs_local_new(const char *filename, int optargc, char* optargv[]) {
    //Number of arguments check
    int err_code = nb_arguments_required(&optargc, 2);
    M_REQUIRE(err_code == ERR_NONE, err_code,"Wrong number of arguments", "" );

    // NULL pointer check
    err_code = non_null_checker(filename, optargc, optargv);
    M_REQUIRE(err_code == ERR_NONE, err_code , "NULL pointer exception", "");

    char* key = optargv[0];
    char* pwd = optargv[1];

    struct CKVS myCKVS;

    struct ckvs_memrecord mymr;

    ckvs_entry_t *newEntry;

    // Opening of the database and initialization of myCKVS with the right header and entries
    error_code code = ckvs_open(filename,&myCKVS);

    M_REQUIRE_ELSE_CLOSE_CKVS(code == ERR_NONE, &myCKVS, code, "could not open %s", filename);

    // Computation of the stretched, auth and c1 keys
    code = ckvs_client_encrypt_pwd(&mymr, key, pwd);

    M_REQUIRE_ELSE_CLOSE_CKVS(code == ERR_NONE, &myCKVS, code, "could not compute the keys", "");

    code = ckvs_new_entry(&myCKVS, key, &mymr.auth_key, &newEntry);

    M_REQUIRE_ELSE_CLOSE_CKVS(code == ERR_NONE, &myCKVS, code, "could not create new entry", "");

    ckvs_close(&myCKVS);

    return ERR_NONE;
}
