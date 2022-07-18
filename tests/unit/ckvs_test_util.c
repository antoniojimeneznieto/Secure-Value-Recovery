/**
 * @file ckvs_test_util.c
 * @brief PPS (CS-212) Utilities for tests for the CryptKVS project
 *
 * @author A. Clergeot
 * @date 2021
 */

#include "ckvs_test_util.h"

int dump_db(FILE* file, const ckvs_header_t* header, const ckvs_entry_t* entries)
{
    if (fwrite(header, sizeof(ckvs_header_t), 1, file) != 1) 
        return -1;
    if (fwrite(entries, sizeof(ckvs_entry_t), header->table_size, file) != header->table_size) 
        return -1;
    return 0;
}

int create_file_and_dump_db(const char* filename, const ckvs_header_t* header, const ckvs_entry_t* entries)
{
    FILE* f = fopen(filename, "wb");
    if (f == NULL) return -1;

    int err = dump_db(f, header, entries);
    fclose(f);
    return err;
}


int create_file_and_dump_value(const char* filename, const void* buffer, size_t bytes)
{
    FILE* f = fopen(filename, "wb");
    if (f == NULL) return -1;

    int err = 0;
    if (fwrite(buffer, bytes, 1, f) != 1)
        err = 1;

    fclose(f);
    return err;
}
