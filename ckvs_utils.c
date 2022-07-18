/**
 * @file ckvs_utils.c
 * @headerfile ckvs_utils.h
 * @brief ckvs_utils -- regroups some useful utility function
 */

#include <stdio.h>
#include <openssl/sha.h>
#include "ckvs_utils.h"
#include "ckvs.h"
#include "util.h"
#include <stdlib.h>

void print_header(const struct ckvs_header* header) {
    // NULL pointer checks
    if(header == NULL) {
        debug_printf("NULL argument while printing the header");
        return;
    }
    pps_printf("CKVS Header type       : %s\n", header->header_string);
    pps_printf("CKVS Header version    : %u\n", header->version);
    pps_printf("CKVS Header table_size : %u\n", header->table_size);
    pps_printf("CKVS Header threshold  : %u\n", header->threshold_entries);
    pps_printf("CKVS Header num_entries: %u\n", header->num_entries   );
}

void print_client_entry(const struct ckvs_entry* entry) {

    // NULL pointer checks
    if(entry == NULL) {
        debug_printf("NULL argument while printing the entry");
        return;
    }
    pps_printf("Key       : " STR_LENGTH_FMT(CKVS_MAXKEYLEN) "\n" , entry->key);
}

void print_entry(const struct ckvs_entry* entry) {

    // NULL pointer checks
    if(entry == NULL) {
        debug_printf("NULL argument while printing the entry");
        return;
    }
    pps_printf("    Key   : " STR_LENGTH_FMT(CKVS_MAXKEYLEN) "\n" , entry->key);
    pps_printf("    Value : off %lu len %lu\n"                    , entry->value_off, entry->value_len);
    print_SHA(  "    Auth  "                                       , &entry->auth_key);
    print_SHA(  "    C2    "                                       , &entry->c2);
}

void hex_encode(const uint8_t *in, size_t len, char *out) {

    M_REQUIRE(in  != NULL, , "NULL in argument while encoding in hexadecimal", "");
    M_REQUIRE(out != NULL, , "NULL out argument while encoding in hexadecimal", "");
    M_REQUIRE(len > 0,     , "Negative length for input buffer while trying to encode in hexadecimal", "");

    for (size_t i = 0; i < len; i++) {
        sprintf(out + 2*i, "%02x", in[i]);
    }
}

int hex_decode(const char *input, uint8_t *output) {

    M_REQUIRE(input != NULL, -1, "NULL in argument while decoding in hexadecimal", "");
    M_REQUIRE(output != NULL, -1, "NULL out argument while decoding in hexadecimal", "");

    char* nibbles = calloc(2, sizeof(char));

    size_t len = strlen(input);

    char* temp = calloc(len, sizeof(char));

    // if size is odd, we add a 0 at the start to make it even
    if(len % 2 == 1) {
        temp = realloc(temp, (len + 1)*sizeof(char));
        *temp = '0';
        memcpy(temp + 1, input, len*sizeof(char));
        len++;
    }
    else {
        memcpy(temp, input, len*sizeof(char));
    }

    int k = 0; // an iterator

    for (size_t i = 0; i < len; i = i + 2) {

        //Copy 2 bytes from input to nibbles
        char* ptr = memcpy(nibbles, temp + i, 2);

        M_REQUIRE_ELSE_RUN_EXIT_CODE(ptr != NULL,
                                     {
                                         free(temp);
                                         free(nibbles);
                                     }
        ,ERR_INVALID_ARGUMENT, "parameter %s is NULL", ptr
        );

        //Convert the 2 bytes
        errno = 0;
        *(output + k) = (uint8_t) strtoul((char*) nibbles, NULL, 16);

        k++;

        M_REQUIRE_ELSE_RUN_EXIT_CODE(errno == 0,
                                     {
                                         free(temp);
                                         free(nibbles);
                                     }
        ,-1, "Unable to convert string to hexadecimal", ""
        );
    }

    free(temp);
    free(nibbles);
    return k; // the length of the decoded input
}

void SHA256_to_string(const struct ckvs_sha *sha, char *buf) {

    // NULL pointer checks
    M_REQUIRE(sha != NULL, , "NULL sha argument while encoding in hexadecimal", "");
    M_REQUIRE(buf != NULL, , "NULL buf argument while encoding in hexadecimal", "");

    hex_encode(sha->sha, SHA256_DIGEST_LENGTH, buf);
}

int SHA256_from_string(const char *in, struct ckvs_sha *sha) {

    // NULL pointer checks
    M_REQUIRE(in != NULL, -1, "NULL in argument while decoding in hexadecimal", "");
    M_REQUIRE(sha != NULL, -1, "NULL sha argument while decoding in hexadecimal", "");

    int len = hex_decode(in, sha->sha);

    M_REQUIRE(len != -1, -1, "Unable to decode hexadecimal string", "");

    return len;
}

void print_SHA(const char *prefix, const struct ckvs_sha *sha) {

    // NULL pointer checks
    M_REQUIRE(sha  != NULL, , "NULL sha argument while encoding in hexadecimal", "");

    char buffer[SHA256_PRINTED_STRLEN + 1];
    SHA256_to_string(sha, buffer);
    pps_printf("%-5s: %s\n", prefix, buffer);
}

int ckvs_cmp_sha(const struct ckvs_sha *a, const struct ckvs_sha *b) {

    // NULL pointer checks
    M_REQUIRE_NON_NULL(a);
    M_REQUIRE_NON_NULL(b);

    // Compares the first SHA256_DIGEST_LENGTH bytes of the memory areas of a and b
    return memcmp(a, b, SHA256_DIGEST_LENGTH);
}