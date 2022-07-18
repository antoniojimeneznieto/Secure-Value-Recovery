/**
 * @file ckvs_io.c
 * @headerfile ckvs_io-h
 * @brief ckvs_io - IO operations for a local database
 * @author
 */
#pragma once

#include <stdint.h> // for uint64_t
#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_crypto.h"
#include "ckvs_utils.h"
#include <stdlib.h> // malloc

#include <unistd.h>

/**
 * @brief Computes the hashkey of a key
 *
 * @param ckvs (const struct CKVS*) the ckvs database
 * @param key (cconst char*) the key to transform into the hashkey
 * @return uint32_t, the computed hashkey
 */

static uint32_t ckvs_hashkey(const struct CKVS *ckvs, const char *key) {

    // NULL pointer checks
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);

    ckvs_sha_t keySHA256;
    memset(&keySHA256, 0, sizeof(ckvs_sha_t));

    SHA256(key, strlen(key), &keySHA256);

    uint32_t hashkey;
    memcpy(&hashkey, &keySHA256, 4); // take the first 4 bytes of the generated SHA key

    hashkey = (ckvs->header.table_size - 1) & hashkey; // use table_size - 1 as the mask

    return hashkey;
}

/**
 * @brief Checks if a given header is valid
 *
 * @param header (const ckvs_header_t) the header to validate
 * @return int, 1 if the header is valid, else 0
 */

static int check_header_validity(const ckvs_header_t header) {

    int header_is_valid = 0;

    header_is_valid =
            (strncmp(header.header_string, CKVS_HEADERSTRING_PREFIX, strlen(CKVS_HEADERSTRING_PREFIX)) == 0)
            && (header.version == CKVS_CURRENT_VERSION)
            && ((header.table_size & (header.table_size - 1)) == 0);

    return header_is_valid;
}


int ckvs_find_entry(struct CKVS *ckvs, const char *key, const struct ckvs_sha *auth_key, struct ckvs_entry **e_out) {

    // NULL pointer checks
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(auth_key);
    M_REQUIRE_NON_NULL(e_out);

    // If we find the key we will update it to 1
    int keyFound = 0;

    // If we can validate the key found with the auth_key we will update it to 1
    int auth_key_is_correct = 0;

    uint32_t index = ckvs_hashkey(ckvs, key);

    unsigned long len = strnlen(key, CKVS_MAXKEYLEN) >= strnlen(ckvs->entries[index].key, CKVS_MAXKEYLEN) ?
                        strnlen(key, CKVS_MAXKEYLEN) :  strnlen(ckvs->entries[index].key, CKVS_MAXKEYLEN);
    len = len >= CKVS_MAXKEYLEN ? CKVS_MAXKEYLEN : len;

    if(strncmp(ckvs->entries[index].key, key, len) == 0) {
        keyFound = 1;
        // we compare the auth_key. If they are equal ckvs_cmp_sha will return 0
        if(ckvs_cmp_sha(&ckvs->entries[index].auth_key, auth_key) == 0) {
            // Update the entry pointer to the entry found
            *e_out = &ckvs->entries[index];
            auth_key_is_correct = 1;
        }
    }

    if(keyFound && auth_key_is_correct) { return ERR_NONE; }

    // Loop over all entries starting from the computed index to find the entry
    for(unsigned int k = 1; k < ckvs->header.table_size; k++) {
        unsigned int i = (index + k) % ckvs->header.table_size;

        if(strncmp(ckvs->entries[i].key, key, len) == 0) {
            keyFound = 1;
            // we compare the auth_key. If they are equal ckvs_cmp_sha will return 0
            if(ckvs_cmp_sha(&ckvs->entries[i].auth_key, auth_key) == 0) {
                // Update the entry pointer to the entry found
                *e_out = &ckvs->entries[i];
                auth_key_is_correct = 1;
            }
        }
    }

    // If we could not find the key we return the error
    M_REQUIRE((keyFound == 1), ERR_KEY_NOT_FOUND, "%s key not found in\n", key);

    // If we could not validate the auth_keys we return the error
    M_REQUIRE((auth_key_is_correct == 1), ERR_DUPLICATE_ID, "duplicate id for key %s\n", key);

    return ERR_NONE;
}

int ckvs_open(const char *filename, struct CKVS *ckvs) {

    // NULL pointer checks
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(ckvs);

    // Initialize the ckvs
    memset(ckvs, 0, sizeof(ckvs_t));

    // Open the file
    FILE *entry = NULL;
    size_t size_read = 0;

    entry = fopen(filename, "rb+"); // read and writing mode

    M_REQUIRE_ELSE_RUN_EXIT_CODE(entry != NULL,
        {
            ckvs_close(ckvs);
        },
        ERR_IO, "could not open %s\n", filename);

    ckvs->file = entry;

    // Read the header
    ckvs_header_t header;
    memset(&header, 0, sizeof(header));

    if (!feof(entry)) {
        size_read += fread(&header, sizeof(ckvs_header_t), 1, entry);

         M_REQUIRE_ELSE_CLOSE_CKVS(size_read == 1, ckvs, ERR_IO, "could not read header in %s\n", filename);

        int header_is_valid = check_header_validity(header);

         M_REQUIRE_ELSE_CLOSE_CKVS(header_is_valid, ckvs, ERR_CORRUPT_STORE, "could not validate header in %s\n", filename);

        // Save the validated header
        ckvs->header = header;
    }

    ckvs->entries = calloc(ckvs->header.table_size, sizeof(ckvs_entry_t));

    // Reset the size read and read all the entries
    size_read = 0;
    for (int i = 0; i < ckvs->header.table_size; ++i) {
        // initialize the entry
        ckvs_entry_t *table_entry = &ckvs->entries[i];

        // Read the binary entry structure
        if (!feof(entry)) {
            size_read += fread(table_entry, sizeof(ckvs_entry_t), 1, entry);
        }
    }

    M_REQUIRE_ELSE_CLOSE_CKVS(size_read == header.table_size, ckvs, ERR_IO, "invalid number of entires in %s."
                                                                            "There should be %ld entries "
                                                                            "but there are %d entries\n",
                                                                            filename, size_read, header.table_size);

    if(size_read != header.table_size) {
        ckvs_close(ckvs);
        M_EXIT(ERR_IO, "invalid number of entries in %s."
                       "There should be %ld entries "
                       "but there are %d entries\n",
               filename, size_read, header.table_size);
    }

    return ERR_NONE;
}

void ckvs_close(struct CKVS *ckvs){
    if (ckvs != NULL && ckvs->file != NULL) {
        fclose(ckvs->file);
        ckvs->file = NULL;
    }
    if(ckvs != NULL && ckvs->entries != NULL) {
        free(ckvs->entries);
        ckvs->entries = NULL;
        ckvs = NULL;
    }
}

static int ckvs_write_header_to_disk(struct CKVS *ckvs) {
    M_REQUIRE_NON_NULL(ckvs);

    // Seek the start of the encrypted file
    if(fseek(ckvs->file, 0, SEEK_SET) != 0) {
        ckvs_close(ckvs);
        M_EXIT(ERR_CORRUPT_STORE, "could not read ckvs file\n", "");
    }

    // Write our updated header
    if(fwrite(&(ckvs->header), sizeof(ckvs_header_t), 1, ckvs->file) != 1) {
        ckvs_close(ckvs);
        M_EXIT(ERR_CORRUPT_STORE, "could not update entry in ckvs file\n", "");
    }

    return ERR_NONE;
}

static int ckvs_write_entry_to_disk(struct CKVS *ckvs, uint32_t idx) {
    M_REQUIRE_NON_NULL(ckvs);

    // Seek the entry position in the encrypted file
    if(fseek(ckvs->file, sizeof(ckvs_header_t) + idx * sizeof(ckvs_entry_t), SEEK_SET) != 0) {
        ckvs_close(ckvs);
        M_EXIT(ERR_CORRUPT_STORE, "could not read ckvs file\n", "");
    }

    // Write our updated entry
    if(fwrite(&(ckvs->entries[idx]), sizeof(ckvs_entry_t), 1, ckvs->file) != 1) {
        ckvs_close(ckvs);
        M_EXIT(ERR_CORRUPT_STORE, "could not update entry in ckvs file\n", "");
    }

    return ERR_NONE;
}

int ckvs_write_encrypted_value(struct CKVS *ckvs, struct ckvs_entry *e, const unsigned char *buf, uint64_t buflen) {
    // NULL pointer checks
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(e);
    M_REQUIRE_NON_NULL(buf);

    //Seek end of file
    if(fseek(ckvs->file, 0, SEEK_END) != 0) {
        ckvs_close(ckvs);
        M_EXIT(ERR_CORRUPT_STORE, "could not read ckvs file\n", "");
    }

    int value_off = ftell(ckvs->file);

    // Write our new encrypted value at the end of the file
    if(fwrite(buf, buflen, 1, ckvs->file) != 1) {
        ckvs_close(ckvs);
        M_EXIT(ERR_CORRUPT_STORE, "could not write value in ckvs file\n", "");
    }

    // Update the entry. Note that C2 value has already been updated at this stage.
    e->value_off = value_off;
    e->value_len = buflen;

    uint32_t idx = e - ckvs->entries;

    return ckvs_write_entry_to_disk(ckvs, idx);
}

int read_content(FILE* file, long offset, size_t size, char** buffer_ptr) {

    // NULL pointer checks
    M_REQUIRE_NON_NULL(file);
    M_REQUIRE_NON_NULL(buffer_ptr);


    //get the size of the file
    if(fseek(file, offset, SEEK_SET) != 0) {
        //fclose(file);
        M_EXIT(ERR_IO, "could not open file\n", "");
    }

    char* content = NULL;
    size_t size_read = 0;

    content = calloc(1, size);

    if(content == NULL) {
        //fclose(file);
        M_EXIT(ERR_OUT_OF_MEMORY, "system out of memory\n", "");
    }

    size_read = fread(content,size, 1, file);

    if(size_read != 1) {
        free(content);
        content = NULL;
        //fclose(file);
        M_EXIT(ERR_IO, "could not read file\n", "");
    }

    //fclose(file);

    *buffer_ptr = content;

    return ERR_NONE;
}

int read_value_file_content(const char* filename, char** buffer_ptr, size_t* buffer_size) {
    // NULL pointer checks
    M_REQUIRE_NON_NULL(filename);
    M_REQUIRE_NON_NULL(buffer_size);
    M_REQUIRE_NON_NULL(buffer_ptr);

    FILE* entry = NULL;

    entry = fopen(filename, "r");

    if(entry == NULL) {
        fclose(entry);
        M_EXIT(ERR_IO, "could not open %s\n", filename);
    }

    //get the size of the file
    if(fseek(entry, 0, SEEK_END) != 0) {
        fclose(entry);
        M_EXIT(ERR_IO, "could not open %s\n", filename);
    }

    size_t file_size = ftell(entry);
    // put the head at start of the file
    if(fseek(entry, 0, SEEK_SET) != 0) {
        fclose(entry);
        M_EXIT(ERR_IO, "could not seek file size in %s\n", filename);
    }

    char* content = NULL;
    size_t size_read = 0;

    content = calloc(file_size + 1, sizeof(char)); // It must end in '\0' therefore, we add a +1

    if(content == NULL) {
        fclose(entry);
        M_EXIT(ERR_OUT_OF_MEMORY, "system out of memory\n", "");
    }

    size_read = fread(content,file_size, 1, entry);

    if(size_read != 1) {
        free(content);
        content = NULL;
        fclose(entry);
        M_EXIT(ERR_IO, "could not read %s\n", filename);
    }


    fclose(entry);

    *buffer_ptr = content;
    *buffer_size = file_size + 1;

    return ERR_NONE;
}

int ckvs_new_entry(struct CKVS *ckvs, const char *key, struct ckvs_sha *auth_key, struct ckvs_entry **e_out) {
    // NULL pointer checks
    M_REQUIRE_NON_NULL(ckvs);
    M_REQUIRE_NON_NULL(key);
    M_REQUIRE_NON_NULL(auth_key);
    M_REQUIRE_NON_NULL(e_out);

    ckvs_entry_t newEntry;
    memset(&newEntry, 0, sizeof(ckvs_entry_t));

    // Check that the number of entries does not surpass the threshold
    M_REQUIRE(ckvs->header.num_entries < ckvs->header.threshold_entries, ERR_MAX_FILES, "Too many entries: %d entries \n", ckvs->header.threshold_entries);

    // Check that the key is not already in use
    ckvs_entry_t *entry;
    int code = ckvs_find_entry(ckvs, key, auth_key, &entry);
    M_REQUIRE(code == ERR_KEY_NOT_FOUND, ERR_DUPLICATE_ID, "The key %s is already in use\n", *key);

    size_t key_length = strnlen(key, CKVS_MAXKEYLEN + 1);

    // Check that the key is not too big (too big : key_length == CKVS_MAXKEYLEN + 1)
    M_REQUIRE(key_length <= CKVS_MAXKEYLEN, ERR_INVALID_ARGUMENT, "The key length is bigger than %d", CKVS_MAXKEYLEN);

    // Input the new keys in our new entry
    strncpy(newEntry.key, key, key_length);
    memcpy(&newEntry.auth_key, auth_key, sizeof(ckvs_sha_t));

    uint32_t sha = ckvs_hashkey(ckvs, key); // Index in the entries array to write on

    // Find a suitable index to put our new entry
    uint32_t idx = 0;

    for(unsigned int k = 0; k < ckvs->header.table_size; k++) {

        idx = (sha + k) % ckvs->header.table_size;

        if(strnlen(ckvs->entries[idx].key, CKVS_MAXKEYLEN) == 0) {
            break;
        }
    }

    // Save our new entry in the ckvs
    memcpy(&ckvs->entries[idx], &newEntry, sizeof(ckvs_entry_t));

    // Update the number of entries
    ckvs->header.num_entries += 1;
    *e_out = &ckvs->entries[idx];

    code = ckvs_write_header_to_disk(ckvs);

    M_REQUIRE(code == ERR_NONE, code, "Unable to write header to disk", "");

    code = ckvs_write_entry_to_disk(ckvs, idx);

    M_REQUIRE(code == ERR_NONE, code, "Unable to write new entry to disk", "");


    return ERR_NONE;
}