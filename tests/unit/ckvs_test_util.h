
/**
 * @file ckvs_test_util.h
 * @brief PPS (CS-212) Utilities for tests for the CryptKVS project
 *
 * @author A. Clergeot
 * @date 2021
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ckvs.h"
#include "ckvs_io.h"

#define DUMMY_NAME "./dummy.ckvs"
#define NON_EXISTING_CKVS "./does_not_exist.ckvs"

/**
 * Shorthand to implement a simple pps_printf that does nothing
 */
#define IMPLEMENT_MUTED_PPS_PRINTF int pps_printf(const char* __restrict__ format, ...) { (void) format; return 0; }


/**
 * @brief Initializes a ckvs_header with the given var_name and other parameters
 * @param var_name the name of the created variable 
 * @param header_str (const char*)
 * @param version (uint32_t)
 * @param table_size (uint32_t)
 * @param threshold (uint32_t)
 * @param num_entries (uint32_t)
 */
#define init_header(var_name, header_str, version, table_size, threshold, num_entries) \
    ckvs_header_t var_name = { { 'a' }, version, table_size, threshold, num_entries }; \
    strncpy(var_name.header_string, header_str, CKVS_HEADERSTRINGLEN)


// ckvs.entries is an array

/**
 * @brief Initializes a struct CKVS with the given var_name, 
 * with a valid header and and an array of empty entries.
 * @param var_name the name of the created variable
 * @param table_size (uint32_t)
 * @param threshold (uint32_t)
 */
#define init_ckvs(var_name, table_size, threshold) \
    struct CKVS var_name = { \
        .header = { CKVS_HEADERSTRING_PREFIX " v1", 1, table_size, threshold, 0 }, \
        .entries = { 0 }, \
        .file = NULL, \
    }

/**
 * @brief Frees memory after a init_ckvs()
 * @param ckvs (struct CKVS) the variable to release
 */
#define release_ckvs(ckvs)
// no op


/**
 * @brief Asserts that the ckvs_entry_t at index 'entry_idx' stored in the given 'file'
 * is equal to the given 'expected_ptr'
 * @param file (FILE*)
 * @param entry_idx (unsigned int/long)
 * @param expected_ptr (ckvs_entry_t*)
 */
#define assert_stored_entry_eq(file, entry_idx, expected_ptr) \
    do { \
        ckvs_entry_t read_entry; \
        ck_assert_int_eq(fseek(file, sizeof(ckvs_header_t) + sizeof(ckvs_entry_t) * (entry_idx), SEEK_SET), 0); \
        ck_assert_int_eq(fread(&read_entry, sizeof(ckvs_entry_t), 1, file), 1); \
        ck_assert_int_eq(memcmp(&read_entry, expected_ptr, sizeof(ckvs_entry_t)), 0); \
    } while (0)


/**
 * @brief Dumps the header and entries into the given file
 * @param file (FILE*)
 * @param header (const ckvs_header_t*), pointing to a non NULL header
 * @param entries (const ckvs_entry_t*), an array of length header->table_size 
 */
int dump_db(FILE* file, const ckvs_header_t* header, const ckvs_entry_t* entries);

/**
 * @brief Creates a file 'filename' and dumps the header and entries into it.
 * @param filename (const char*)
 * @param header (const ckvs_header_t*), pointing to a non NULL header
 * @param entries (const ckvs_entry_t*), an array of length header->table_size 
 */
int create_file_and_dump_db(const char* filename, const ckvs_header_t* header, const ckvs_entry_t* entries);

/**
 * @brief Creates a file 'filename' and dumps the buffer into it.
 * @param filename (const char*)
 * @param buffer (const void*), pointing to the data to dump
 * @param bytes (size_t), the number of bytes to write
 */
int create_file_and_dump_value(const char* filename, const void* buffer, size_t bytes);
