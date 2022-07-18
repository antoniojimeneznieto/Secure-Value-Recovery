/**
 * @file ckvs_rpc.c
 * @brief RPC handling using libcurl
 * @author E. Bugnion
 *
 * Includes example from https://curl.se/libcurl/c/getinmemory.html
 */
#include <stdlib.h>

#include "ckvs_rpc.h"
#include "error.h"
#include "util.h"
#include "ckvs_utils.h"

/**
 * ckvs_curl_WriteMemoryCallback -- lifted from https://curl.se/libcurl/c/getinmemory.html
 *
 * @brief Callback that gets called when CURL receives a message.
 * It writes the payload inside ckvs_connection.resp_buf.
 * Note that it is already setup in ckvs_rpc_init.
 *
 * @param contents (void*) content received by CURL
 * @param size (size_t) size of an element of of content. Always 1
 * @param nmemb (size_t) number of elements in content
 * @param userp (void*) points to a ckvs_connection (set with the CURLOPT_WRITEDATA option)
 * @return (size_t) the number of written bytes, or 0 if an error occured
 */
static size_t ckvs_curl_WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct ckvs_connection *conn = (struct ckvs_connection *)userp;

    char *ptr = realloc(conn->resp_buf, conn->resp_size + realsize + 1);
    if(!ptr) {
        /* out of memory! */
        debug_printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    conn->resp_buf = ptr;
    memcpy(&(conn->resp_buf[conn->resp_size]), contents, realsize);
    conn->resp_size += realsize;
    conn->resp_buf[conn->resp_size] = 0;

    return realsize;
}

int ckvs_rpc_init(struct ckvs_connection *conn, const char *url)
{
    M_REQUIRE_NON_NULL(conn);
    M_REQUIRE_NON_NULL(url);
    bzero(conn, sizeof(*conn));

    conn->url  = url;
    conn->curl = curl_easy_init();
    if (conn->curl == NULL) {
        return ERR_OUT_OF_MEMORY;
    }
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, ckvs_curl_WriteMemoryCallback);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, (void *)conn);

    return ERR_NONE;
}

void ckvs_rpc_close(struct ckvs_connection *conn)
{
    if (conn == NULL)
        return;

    if (conn->curl) {
        curl_easy_cleanup(conn->curl);
    }
    if (conn->resp_buf) {
        free(conn->resp_buf);
    }
    bzero(conn, sizeof(*conn));
}

int ckvs_rpc(struct ckvs_connection *conn, const char *GET)
{
    // NULL check
    M_REQUIRE_NON_NULL(conn);
    M_REQUIRE_NON_NULL(GET);

    // Concatenation of url and GET
    size_t size = strlen(GET) + strlen(conn->url);
    char* url_get = calloc(size + 1, sizeof(char));
    strcpy(url_get, conn->url);
    strcat(url_get, GET); // We concatenate conn->url with GET
    url_get[size] = '\0';

    CURLcode ret = curl_easy_setopt(conn->curl, CURLOPT_URL, url_get);

    M_REQUIRE_ELSE_RUN_EXIT_CODE(ret != CURLE_OUT_OF_MEMORY,
                                 {
                                     ckvs_rpc_close(conn);
                                     free(url_get);
                                 }
                                 ,ERR_OUT_OF_MEMORY, "Insufficient heap space", ""
    );

    M_REQUIRE_ELSE_RUN_EXIT_CODE(conn->curl != NULL,
                                 {
                                     ckvs_rpc_close(conn);
                                     free(url_get);
                                 }
                                 ,ERR_INVALID_ARGUMENT, "Invalid argument", ""
    );

    ret = curl_easy_perform(conn->curl);

    M_REQUIRE_ELSE_RUN_EXIT_CODE(ret == CURLE_OK,
                                 {
                                     ckvs_rpc_close(conn);
                                     free(url_get);
                                 }
                                ,ERR_TIMEOUT, "Impossible to perform curl_easy: TIMEOUT", ""
    );

    free(url_get);
    return ERR_NONE;
}


int ckvs_post(struct ckvs_connection* conn, const char* GET, const char* POST) {

    M_REQUIRE_NON_NULL(conn);
    M_REQUIRE_NON_NULL(GET);

    M_REQUIRE_NON_NULL(conn->curl);

    // Concatenation of url and GET
    size_t size = strlen(GET) + strlen(conn->url);
    char* url_get = calloc(size + 1, sizeof(char));
    strcpy(url_get, conn->url);
    strcat(url_get, GET); // We concatenate conn->url with GET
    url_get[size] = '\0';

    CURLcode ret = curl_easy_setopt(conn->curl, CURLOPT_URL, url_get);

    struct curl_slist* slist = NULL;
    // Add to the header list "Content-Type: application/json"
    slist = curl_slist_append(slist, "Content-Type: application/json");

    ret = curl_easy_setopt(conn->curl, CURLOPT_HTTPHEADER, slist);

    size = strlen(POST);
    ret = curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDSIZE, (long) size);

    ret = curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDS, POST);

    ret = curl_easy_perform(conn->curl);

    M_REQUIRE_ELSE_RUN_EXIT_CODE(conn->resp_size == 0,
                                 {
                                     pps_printf("%s", conn->resp_buf);
                                     free(url_get);
                                     curl_slist_free_all(slist);
                                 }
    ,ERR_IO, "Response size not 0", ""
    );

    ret = curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDSIZE, 0L);

    ret = curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDS, "");

    ret = curl_easy_perform(conn->curl);

    M_REQUIRE_ELSE_RUN_EXIT_CODE(conn->resp_size == 0,
                                 {
                                     pps_printf("%s", conn->resp_buf);
                                     free(url_get);
                                     curl_slist_free_all(slist);
                                 }
    ,ERR_IO, "Response size not 0", ""
    );

    // Free the slist
    free(url_get);
    curl_slist_free_all(slist);

    return ERR_NONE;


}


