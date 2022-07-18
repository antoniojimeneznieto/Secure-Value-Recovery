/**
 * @file ckvs_rpc.h
 * @brief client-side RPC using CURL
 * @author E Bugnion
 */

#pragma once
#include <curl/curl.h>

/**
 * @brief maximal size of the encrypted value.  hex-encoded is 2x
 */
#define CKVS_MAX_VALUE_LEN_HTTP_QUERY (14*32)

/**
 * @brief Holds the client state that represents a connection to a remote CKVS server
 */
typedef struct ckvs_connection {
    CURL *curl;         /**< CURL instance used for the connection */
    const char *url;    /**< url to the remote server */
    char *resp_buf;     /**< buffer that will hold the response of the server */
    size_t resp_size;   /**< size of resp_buf */
} ckvs_connection_t;

/**
 * @brief Initializes connection to the remote server at url.
 * @param conn (struct ckvs_connection*) the connection to initialize
 * @param url (const char*) target URL (string is not copied)
 * @return int, error code
 */
int ckvs_rpc_init(struct ckvs_connection *conn, const char *url);

/**
 * @brief Cleans up connection to remote server.
 * @param conn (struct ckvs_connection*) the connection to cleanup
 */
void ckvs_rpc_close(struct ckvs_connection *conn);

/**
 * @brief Sends an HTTP GET request to the connected server,
 * using the url and GET payload.
 *
 * @param conn (struct ckvs_connection*) the connection to the server
 * @param GET (const char*) the GET payload
 * @return int, error code
 */
int ckvs_rpc(struct ckvs_connection *conn, const char *GET);

/**
 * @brief Sends an HTTP POST request to the connected server,
 * using its url, and the GET and POST payloads.
 *
 * @param conn (struct ckvs_connection*) the connection to the server
 * @param GET (const char*) the GET payload. Should already contain the fields "name" and "offset".
 * @param POST (const char*) the POST payload
 * @return int, error code
 */
int ckvs_post(struct ckvs_connection* conn, const char* GET, const char* POST);

