/**
 * @file ckvs.h
 * @brief On-disk data structures for CKVS (encrypted key-value store)
 */

#pragma once

#include "ckvs_utils.h"
#include "error.h"
#include <stdint.h>
#include <stdio.h>

/**
 * @brief Maximum length of the field header_string in ckvs_header.
 */
#define CKVS_HEADERSTRINGLEN 32
/**
 * @brief Value of the prefix header_string in ckvs_header.
 */
#define CKVS_HEADERSTRING_PREFIX "CS212 CryptKVS"
/**
 * @brief Value of the current CKVS version.
 */
#define CKVS_CURRENT_VERSION 1
/**
 * @brief Maximum length for an entry's key.
 */
#define CKVS_MAXKEYLEN  32
/**
 * @brief Absolute maximum table_size for a CKVS database.
 */
#define CKVS_MAX_ENTRIES (1<<22)

/**
 * @brief Only for the beginning of the project.
 */
#define CKVS_FIXEDSIZE_TABLE (1<<6)

/**
 * @brief Represents a CKVS database header.
 */
struct ckvs_header {
    char header_string[CKVS_HEADERSTRINGLEN]; /**< should start with CKVS_HEADERSTRING_PREFIX */
    uint32_t  version;                        /**< should be 1 */
    uint32_t  table_size;                     /**< must be a power of 2 */
    uint32_t  threshold_entries;              /**< max effective capacity */
    uint32_t  num_entries;                    /**< number of valid entries */
};

/**
 * @brief Represents a CKVS database entry.
 */
struct ckvs_entry {
    char key[CKVS_MAXKEYLEN];  /**< not (necessarily) null-terminated */
    struct ckvs_sha auth_key;  /**< as specified by protocol */
    struct ckvs_sha c2;        /**< as specified by protocol */
    uint64_t value_off;        /**< offset of encrypted secret value in database */
    uint64_t value_len;        /**< length of encrypted secret value in database */
};

/**
 * @brief ckvs_header_t -- Convenience typedef of ckvs_header
 */
typedef struct ckvs_header ckvs_header_t; /**< convenience type of ckvs_header */
/**
 * @brief ckvs_entry_t -- Convenience typedef of ckvs_entry
 */
typedef struct ckvs_entry  ckvs_entry_t; /**< convenience type of ckvs_header */

