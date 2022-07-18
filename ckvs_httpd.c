/**
 * @file ckvs_httpd.c
 * @brief webserver
 */

#include "ckvs.h"
#include "ckvs_io.h"
#include "ckvs_utils.h"
#include "error.h"
#include "ckvs_httpd.h"
#include <assert.h>
#include "libmongoose/mongoose.h"
#include <json-c/json.h>
#include <string.h>
#include <assert.h>
#include <curl/curl.h>
#include "util.h"


// Handle interrupts, like Ctrl-C
static int s_signo;

#define HTTP_ERROR_CODE 500
#define HTTP_OK_CODE 200
#define HTTP_FOUND_CODE 302
#define HTTP_NOTFOUND_CODE 404


/**
 * @brief Sends an http error message
 * @param nc the http connection
 * @param err the error code corresponding the error message
*/
void mg_error_msg(struct mg_connection* nc, int err)
{
    assert(err>=0 && err < ERR_NB_ERR);
    mg_http_reply(nc, HTTP_ERROR_CODE, NULL, "Error: %s", ERR_MESSAGES[err]);
}

/**
 * @brief Handles signal sent to program, eg. Ctrl+C
 */
static void signal_handler(int signo)
{
    s_signo = signo;
}

static void handle_stats_call(struct mg_connection *nc, struct CKVS *ckvs, _unused struct mg_http_message *hm)
{
    M_REQUIRE(nc != NULL, , "NULL nc connexion while handling stats call", "");
    M_REQUIRE(ckvs != NULL, , "NULL ckvs while handling stats call", "");
    M_REQUIRE(hm != NULL, ,"NULL ckvs while handling stats call", "");


    json_object *json = json_object_new_object();

    M_REQUIRE(json != NULL, ,"Unable to a new json object", "");


    json_object* json_header_string = json_object_new_string(ckvs->header.header_string);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_header_string != NULL,
                                 {
                                     json_object_put(json);
                                 }
    ,, "Unable to create json_header_string", ""
    );

    json_object* json_version = json_object_new_int(ckvs->header.version);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_version != NULL,
                                 {
                                     json_object_put(json);
                                 }
    ,, "Unable to create json_version", ""
    );

    json_object* json_table_size = json_object_new_int(ckvs->header.table_size);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_table_size != NULL,
                                 {
                                     json_object_put(json);
                                 }
    ,, "Unable to create json_table_size", ""
    );

    json_object* json_threshold_entries = json_object_new_int(ckvs->header.threshold_entries);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_threshold_entries != NULL,
                                 {
                                     json_object_put(json);
                                 }
    ,, "Unable to create json_threshold_entries", ""
    );

    json_object* json_num_entries = json_object_new_int(ckvs->header.num_entries);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_num_entries != NULL,
                                 {
                                     json_object_put(json);
                                 }
    ,, "Unable to create json_num_entries", ""
    );


    json_object* json_keys = json_object_new_array();
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_keys != NULL,
                                 {
                                     json_object_put(json);
                                 }
    ,, "Unable to create json_keys", ""
    );


    for (size_t i = 0; i < ckvs->header.table_size; ++i) {

        if (strnlen(ckvs->entries[i].key, CKVS_MAXKEYLEN) != 0) {
            char string[CKVS_MAXKEYLEN + 1] = { 0 };
            strncpy(string, ckvs->entries[i].key, CKVS_MAXKEYLEN);
            json_object *json_key = json_object_new_string(string);
            M_REQUIRE_ELSE_RUN_EXIT_CODE(json_key != NULL,
                                         {
                                             json_object_put(json);
                                         }
            ,, "Unable to create json_key number %d", i
            );

            json_object_array_add(json_keys, json_key);
        }
    }

    int code = json_object_object_add(json, "header_string",     json_header_string);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(code == 0,
                                 {
                                     json_object_put(json);
                                 }
    ,, "Unable to add json_header_string to json", ""
    );

    code = json_object_object_add(json, "version",           json_version);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(code == 0,
                                 {
                                     json_object_put(json);
                                 }
    ,, "Unable to add json_version to json", ""
    );

    code = json_object_object_add(json, "table_size",        json_table_size);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(code == 0,
                                 {
                                     json_object_put(json);
                                 }
    ,, "Unable to add json_table_size to json", ""
    );

    code = json_object_object_add(json, "threshold_entries", json_threshold_entries);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(code == 0,
                                 {
                                     json_object_put(json);
                                 }
    ,, "Unable to add json_threshold_entries to json", ""
    );

    code = json_object_object_add(json, "num_entries",       json_num_entries);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(code == 0,
                                 {
                                     json_object_put(json);
                                 }
    ,, "Unable to add json_num_entries to json", ""
    );

    code = json_object_object_add(json, "keys",              json_keys);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(code == 0,
                                 {
                                     json_object_put(json);
                                 }
    ,, "Unable to add json_keys to json", ""
    );

    const char* json_string = json_object_to_json_string(json);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_string != NULL,
                                 {
                                     json_object_put(json);
                                 }
    ,, "Unable to convert json_object to json_string", ""
    );

    // Send the response
    mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n", json_string);
    json_object_put(json);
}

static char* get_urldecoded_argument(struct mg_http_message *hm, const char *arg)
{

    char* buffer = calloc(1024, sizeof(char));
    int length = mg_http_get_var(&hm->query, arg, buffer,1024);

    if(length <= 0) {
        free(buffer);
        return NULL;
    }

    return buffer;
}

static void handle_get_call(struct mg_connection *nc, struct CKVS *ckvs, _unused struct mg_http_message *hm)
{

    M_REQUIRE(nc != NULL, , "NULL nc connexion while handling stats call", "");
    M_REQUIRE(ckvs != NULL, , "NULL ckvs while handling stats call", "");
    M_REQUIRE(hm != NULL, ,"NULL ckvs while handling stats call", "");

    // Extraction of key
    char* key_url = get_urldecoded_argument(hm, "key");
    M_REQUIRE_ELSE_RUN_EXIT_CODE(key_url != NULL,
                                 {
                                     pps_printf("Invalid Key\n");
                                     mg_error_msg(nc, ERR_INVALID_ARGUMENT);
                                 }
    ,, "Unable to allocate memory for key_url", ""
    );

    // Extraction of auth_key
    char* auth_key_url = get_urldecoded_argument(hm, "auth_key");
    M_REQUIRE_ELSE_RUN_EXIT_CODE(auth_key_url != NULL,
                                 {
                                     free(key_url);
                                 }
    ,, "Unable to allocate memory for auth_key_url", ""
    );

    CURL* curl = curl_easy_init();
    size_t size = 0;
    char* key = curl_easy_unescape(curl, key_url, strlen(key_url), &size);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(key != NULL,
                                 {
                                     free(key_url);
                                     free(auth_key_url);
                                     curl_free(curl);
                                 }
    ,, "Unable to unescape key", ""
    );
    curl_easy_cleanup(curl);
    free(key_url);

    ckvs_sha_t auth_key;
    memset(&auth_key, 0, sizeof(ckvs_sha_t));
    SHA256_from_string(auth_key_url, &auth_key);
    free(auth_key_url);

    // Find the entry for key //
    ckvs_entry_t* entry_searched;
    error_code code = ckvs_find_entry(ckvs, key, &auth_key, &entry_searched);

    M_REQUIRE_ELSE_RUN_EXIT_CODE(code == ERR_NONE,
                                 {
                                    pps_printf("Unable to find desired entry\n");
                                    mg_error_msg(nc, code);
                                    curl_free(key);
                                 }
    ,, "Unable to find the entry searched", ""
    );

    M_REQUIRE_ELSE_RUN_EXIT_CODE(entry_searched->value_len > 0,
                                 {
                                     mg_error_msg(nc, ERR_NO_VALUE);
                                     curl_free(key);
                                 }
    ,, "Unable to find the entry searched", ""
    );

    // In case of success we create a JSON
    json_object* json = json_object_new_object();
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json != NULL,
                                 {
                                    curl_free(key);
                                 }
    ,, "Unable to create a new json object", ""
    );

    // We add the c2 key in hexcode
    char hex_c2_key[SHA256_PRINTED_STRLEN];

    SHA256_to_string(&(entry_searched->c2), hex_c2_key);

    json_object* json_hex_c2_key = json_object_new_string(hex_c2_key);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_hex_c2_key != NULL,
                                 {
                                    curl_free(key);
                                    json_object_put(json);

                                 }
    ,, "Unable to create json_hex_c2_key", ""
    );

    char* value;
    read_content(ckvs->file, entry_searched->value_off, entry_searched->value_len, &value);

    char* hex_value = calloc(2*entry_searched->value_len + 1, sizeof(char));
    hex_encode(value, entry_searched->value_len,hex_value);

    free(value);

    json_object* json_value = json_object_new_string(hex_value);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_value != NULL,
                                 {
                                    curl_free(key);
                                     free(hex_value);
                                     json_object_put(json);
                                 }
    ,, "Unable to create json_value", ""
    );

    code = json_object_object_add(json, "c2",  json_hex_c2_key);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(code == 0,
                                 {
                                    curl_free(key);
                                     free(hex_value);
                                     json_object_put(json);
                                 }
    ,, "Unable to add json_hex_c2_key to json", ""
    );
    code = json_object_object_add(json, "data",json_value);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(code == 0,
                                 {
                                    curl_free(key);
                                     free(hex_value);
                                     json_object_put(json);
                                 }
    ,, "Unable to add json_value to json", ""
    );

    const char* json_string = json_object_to_json_string(json);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_string != NULL,
                                 {
                                     curl_free(key);
                                     free(hex_value);
                                     json_object_put(json);
                                 }
    ,, "Unable to convert json_object to json_string", ""
    );

    // Send the response
    mg_http_reply(nc, HTTP_OK_CODE, "Content-Type: application/json\r\n", "%s\n", json_string);
    json_object_put(json);

    curl_free(key);
    free(hex_value);
}

static void handle_set_call(struct mg_connection *nc, struct CKVS *ckvs, _unused struct mg_http_message *hm) {

    // Receive chunks //

    if(hm->body.len > 0) {
        mg_http_upload(nc, hm, "/tmp");
        return;
    }

    /////////////////
    // Execute set //
    ////////////////

    // Extract the key and auth

    char* key_url         = get_urldecoded_argument(hm, "key");
    M_REQUIRE_ELSE_RUN_EXIT_CODE(key_url != NULL,
                                 {
                                     pps_printf("Invalid Key\n");
                                     mg_error_msg(nc, ERR_INVALID_ARGUMENT);
                                 }
    ,, "Unable to allocate memory for key", ""
    );

    char* auth_key_url    = get_urldecoded_argument(hm, "auth_key");
    M_REQUIRE_ELSE_RUN_EXIT_CODE(auth_key_url != NULL,
                                 {
                                     free(key_url);
                                 }
    ,, "Unable to allocate memory for auth_key_url", ""
    );


    char* name            = get_urldecoded_argument(hm, "name");
    M_REQUIRE_ELSE_RUN_EXIT_CODE(name != NULL,
                                 {
                                     free(key_url);
                                     free(auth_key_url);
                                 }
    ,, "Unable to allocate memory for name", ""
    );

    CURL* curl = curl_easy_init();
    size_t size = 0;
    char* key = curl_easy_unescape(curl, key_url, strlen(key_url), &size);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(key != NULL,
                                 {
                                     free(key_url);
                                     free(auth_key_url);
                                     free(name);
                                     curl_easy_cleanup(curl);
                                 }
    ,, "Unable to unescape key", ""
    );

    free(key_url);
    curl_easy_cleanup(curl);

    ckvs_sha_t auth_key;
    memset(&auth_key, 0, sizeof(ckvs_sha_t));
    SHA256_from_string(auth_key_url, &auth_key);

    free(auth_key_url);

    char filename[strlen(name) + strlen("/tmp/") + 1];

    strcpy(filename, "/tmp/");
    strcat(filename, name);

    free(name);


    ////////////////////////////
    // Find the entry for key //
    ///////////////////////////


    ckvs_entry_t* entry_searched;
    error_code code = ckvs_find_entry(ckvs, key, &auth_key, &entry_searched);

    M_REQUIRE_ELSE_RUN_EXIT_CODE(code == ERR_NONE,
                                 {
                                     if(code == ERR_KEY_NOT_FOUND) { mg_error_msg(nc, ERR_KEY_NOT_FOUND); }
                                     if(code == ERR_DUPLICATE_ID)  { mg_error_msg(nc, ERR_DUPLICATE_ID);}

                                     pps_printf("Error while searching for the entry\n");
                                     curl_free(key);
                                 }
    ,, "Unable to find the entry searched", ""
    );

    curl_free(key);


    ////////////////////////////////////
    // Read file located at /tmp/name //
    ///////////////////////////////////


    char* buffer;
    code = read_value_file_content(filename, &buffer, &size);

    M_REQUIRE_ELSE_RUN_EXIT_CODE(code == ERR_NONE,
                                 {
                                     pps_printf("Unable to read file\n");
                                     mg_error_msg(nc, code);
                                 }
    ,, "Unable to read file content", ""
    );


    ///////////////////////////////////
    // Extract JSON values from file //
    //////////////////////////////////


    json_object* json = json_tokener_parse(buffer);

    json_object* json_c2;
    json_object_object_get_ex(json, "c2", &json_c2);
    size = (size_t) json_object_get_string_len(json_c2);
    char c2_string[size + 1];
    strcpy(c2_string, json_object_get_string(json_c2));
    ckvs_sha_t c2;
    SHA256_from_string(c2_string, &c2);

    json_object* json_data;
    json_object_object_get_ex(json, "data", &json_data);
    size = (size_t) json_object_get_string_len(json_data);
    char data_string[size + 1];
    strcpy(data_string, json_object_get_string(json_data));

    unsigned char* message = calloc((size + 1) / 2, sizeof(char));

    hex_decode(data_string, message);

    entry_searched->c2 = c2;

    ckvs_write_encrypted_value(ckvs, entry_searched, message, (size + 1) / 2);

    printf("Code = %d", json_object_put(json));

    mg_http_reply(nc, HTTP_OK_CODE, "", "");

    free(buffer);
    free(message);
}

// ======================================================================
/**
 * @brief Handles server events (eg HTTP requests).
 * For more check https://cesanta.com/docs/#event-handler-function
 */
static void ckvs_event_handler(
struct mg_connection *nc, int ev, void *ev_data, void *fn_data)
{
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    struct CKVS *ckvs = (struct CKVS*) fn_data;

    if (ev != MG_EV_POLL)
        debug_printf("Event received %d", ev);

    switch (ev) {
    case MG_EV_POLL:
    case MG_EV_CLOSE:
    case MG_EV_READ:
    case MG_EV_WRITE:
    case MG_EV_HTTP_CHUNK:
        break;

    case MG_EV_ERROR:
        debug_printf("httpd mongoose error \n");
        break;
    case MG_EV_ACCEPT:
        // students: no need to implement SSL
        assert(ckvs->listening_addr);
        debug_printf("accepting connection at %s\n", ckvs->listening_addr);
        assert (mg_url_is_ssl(ckvs->listening_addr) == 0);
        break;

    case MG_EV_HTTP_MSG:
        if(mg_http_match_uri(hm, "/stats")) handle_stats_call(nc, ckvs, hm);
        else if(mg_http_match_uri(hm, "/get")) handle_get_call(nc, ckvs, hm);
        else if(mg_http_match_uri(hm, "/set")) handle_set_call(nc, ckvs, hm);
        else mg_error_msg(nc, NOT_IMPLEMENTED);
        break;

    default:
        fprintf(stderr, "ckvs_event_handler %u\n", ev);
        assert(0);
    }
}

// ======================================================================
int ckvs_httpd_mainloop(const char *filename, int optargc, char **optargv)
{
    if (optargc < 1)
        return ERR_NOT_ENOUGH_ARGUMENTS;
    else if (optargc > 1)
        return ERR_TOO_MANY_ARGUMENTS;

    /* Create server */

    signal(SIGINT, signal_handler); //adds interruption signals to the signal handler
    signal(SIGTERM, signal_handler);

    struct CKVS ckvs;
    int err = ckvs_open(filename, &ckvs);

    if (err != ERR_NONE) {
        return err;
    }

    ckvs.listening_addr = optargv[0];

    struct mg_mgr mgr;
    struct mg_connection *c;

    mg_mgr_init(&mgr);

    c = mg_http_listen(&mgr, ckvs.listening_addr, ckvs_event_handler, &ckvs);
    if (c==NULL) {
        debug_printf("Error starting server on address %s\n", ckvs.listening_addr);
        ckvs_close(&ckvs);
        return ERR_IO;
    }

    debug_printf("Starting CKVS server on %s for database %s\n", ckvs.listening_addr, filename);

    while (s_signo == 0) {
        mg_mgr_poll(&mgr, 1000); //infinite loop as long as no termination signal occurs
    }
    mg_mgr_free(&mgr);
    ckvs_close(&ckvs);
    debug_printf("Exiting HTTPD server\n");
    return ERR_NONE;
}

