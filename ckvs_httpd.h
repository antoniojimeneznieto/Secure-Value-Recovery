/**
 * @file ckvs_httpd.h
 * @brief server-side operations over network
 */

#pragma once

// maximal size of the encrypted value.  hex-encoded is 2x
#define CKVS_MAX_VALUE_LEN_HTTP_QUERY (14*32)

/**
 * @brief Loops until interrupted by user and serves remote CKVS connections.
 *
 * @param filename (const char*) the path to the CKVS database
 * @param optargc (int) the number of optional arguments that were provided (should be 1)
 * @param optargv (char**) the values of optional arguments that were provided
 * @return int, error code
 */
int ckvs_httpd_mainloop(const char *filename, int optargc, char **optargv);

