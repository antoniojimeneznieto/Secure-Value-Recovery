#include <openssl/rand.h>
#include "ckvs_rpc.h"
#include "error.h"
#include "ckvs.h"
#include "ckvs_utils.h"
#include "json-c/json.h"
#include "ckvs_crypto.h"
#include "openssl/evp.h"
#include "ckvs_io.h"

int ckvs_client_stats(const char *url, int optargc, char **optargv) {
    //Number of arguments checker
    int err_code = nb_arguments_required(&optargc, 0);
    M_REQUIRE(err_code == ERR_NONE, err_code,"Wrong number of arguments", "" );

    // NULL pointer check
    err_code = non_null_checker(url, optargc, optargv);
    M_REQUIRE(err_code == ERR_NONE, err_code , "NULL pointer exception", "");

    ckvs_connection_t conn;
    memset(&conn, 0, sizeof(ckvs_connection_t));

    int code = ckvs_rpc_init(&conn, url);
    code = ckvs_rpc(&conn, "/stats");
    M_REQUIRE(code == ERR_NONE, code, "Impossible to initialize the rpc", "");

    ckvs_header_t header;
    memset(&header, 0, sizeof(ckvs_header_t));

    json_object* json = json_tokener_parse(conn.resp_buf);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     json_object_put(json);
                                 }
    ,ERR_IO, "Impossible to create the json", ""
    );

    json_object* json_header_string = NULL;
    json_object_object_get_ex(json, "header_string", &json_header_string);

    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_header_string != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     json_object_put(json);
                                 }
    ,ERR_IO, "Impossible to create the json_header_string", ""
    );
    strcpy(header.header_string, json_object_get_string(json_header_string));

    json_object* json_version = NULL;
    json_object_object_get_ex(json, "version", &json_version);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_version != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     json_object_put(json);
                                 }
    ,ERR_IO, "Impossible to create the json_version", ""
    );    header.version = (uint32_t) json_object_get_int(json_version);

    json_object* json_table_size = NULL;
    json_object_object_get_ex(json, "table_size", &json_table_size);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_table_size != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     json_object_put(json);
                                 }
    ,ERR_IO, "Impossible to create the json_table_size", ""
    );
    header.table_size = (uint32_t) json_object_get_int(json_table_size);

    json_object* json_threshold_entries = NULL;
    json_object_object_get_ex(json, "threshold_entries", &json_threshold_entries);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_threshold_entries != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     json_object_put(json);
                                 }
    ,ERR_IO, "Impossible to create the json_threshold_entries", ""
    );    header.threshold_entries = (uint32_t) json_object_get_int(json_threshold_entries);


    json_object* json_num_entries = NULL;
    json_object_object_get_ex(json, "num_entries", &json_num_entries);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_num_entries != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     json_object_put(json);
                                 }
    ,ERR_IO, "Impossible to create the json_num_entries", ""
    );
    header.num_entries = (uint32_t) json_object_get_int(json_num_entries);

    json_object* json_keys = NULL;
    json_object_object_get_ex(json, "keys", &json_keys);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_keys != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     json_object_put(json);
                                 }
    ,ERR_IO, "Impossible to create the json_keys", ""
    );
    size_t size = json_object_array_length(json_keys);

    print_header(&header);

    for (size_t i = 0; i < size; ++i) {

        json_object* json_key = json_object_array_get_idx(json_keys,i);
        M_REQUIRE_ELSE_RUN_EXIT_CODE(json_key != NULL,
                                     {
                                         ckvs_rpc_close(&conn);
                                         json_object_put(json);
                                     }
        ,ERR_IO, "Impossible to create the json_key number %d", i
        );

        ckvs_entry_t entry;
        memset(&entry, 0, sizeof(ckvs_entry_t));

        strcpy(entry.key, json_object_get_string(json_key));

        print_client_entry(&entry);
    }

    json_object_put(json);

    ckvs_rpc_close(&conn);

    return code;
}

int ckvs_client_get(const char *url, int optargc, char **optargv) {

    error_code code = nb_arguments_required(&optargc, 2);
    M_REQUIRE(code == ERR_NONE, code,"Wrong number of arguments", "" );

    // NULL pointer check
    code = non_null_checker(url, optargc, optargv);
    M_REQUIRE(code == ERR_NONE, code, "NULL pointer exception", "");

    char key[strlen(optargv[0]) + 1];
    strcpy(key, optargv[0]);
    char pwd[strlen(optargv[1]) + 1];
    strcpy(pwd, optargv[1]);

    ckvs_connection_t conn;
    code = ckvs_rpc_init(&conn, url);

    M_REQUIRE(code == ERR_NONE, code, "Unable to initialize the connexion", "");

    char* key_url = curl_easy_escape(conn.curl, key, 0);
    M_REQUIRE(key_url != NULL, ERR_OUT_OF_MEMORY,"Unable to transform key into url format", "" );

    // Computation of the stretched, auth and c1 keys
    ckvs_memrecord_t mymr;
    code = ckvs_client_encrypt_pwd(&mymr, key, pwd);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(code == ERR_NONE,
                                 {
                                     ckvs_rpc_close(&conn);
                                     curl_free(key_url);
                                 }
    ,code, "It was impossible to generate the auth key", ""
    );

    char auth_string[SHA256_PRINTED_STRLEN];
    SHA256_to_string(&mymr.auth_key, auth_string);

    char GET[strlen(key_url) + strlen(auth_string) + strlen("/get?key=&auth_key=") + 1];

    code = sprintf(GET, "/get?key=%s&auth_key=%s", key_url, auth_string);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(code >= 0,
                                 {
                                     ckvs_rpc_close(&conn);
                                     curl_free(key_url);
                                 }
    ,ERR_IO, "Unable to create GET string", ""
    );

    curl_free(key_url);

    code = ckvs_rpc(&conn, GET);
    M_REQUIRE(code == ERR_NONE, code, "Impossible to initialize the connexion", "");

    json_object* json = json_tokener_parse(conn.resp_buf);

    M_REQUIRE_ELSE_RUN_EXIT_CODE(json != NULL ,
                                 {
                                     pps_printf("%s\n", conn.resp_buf);
                                     ckvs_rpc_close(&conn);
                                 }
    ,ERR_IO, "Impossible to create the json", ""
    );

    json_object* json_c2_string = NULL;
    json_object_object_get_ex(json, "c2", &json_c2_string);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_c2_string != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     json_object_put(json);
                                 }
    ,ERR_IO, "Impossible to create the jason_c2_string", ""
    );
    int size = json_object_get_string_len(json_c2_string);
    char c2[size + 1];
    strcpy(c2, json_object_get_string(json_c2_string));

    ckvs_sha_t c2_sha;
    SHA256_from_string(c2, &c2_sha);

    code = ckvs_client_compute_masterkey(&mymr, &c2_sha);
    M_REQUIRE(code == ERR_NONE, code, "Impossible to compute the master key", "");

    json_object* json_data_string = NULL;
    json_object_object_get_ex(json, "data", &json_data_string);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_data_string != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     json_object_put(json);
                                 }
    ,ERR_IO, "Impossible to create the json_data_string", ""
    );
    size = json_object_get_string_len(json_data_string);
    char* data = calloc(size + 1, sizeof(char));
    M_REQUIRE_ELSE_RUN_EXIT_CODE(data != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     json_object_put(json);
                                 }
    ,ERR_OUT_OF_MEMORY, "Unable to allocate data: Out of memory", ""
    );
    strcpy(data, json_object_get_string(json_data_string));

    unsigned char* inbuf = calloc((size + 1) / 2, sizeof(char));
    M_REQUIRE_ELSE_RUN_EXIT_CODE(inbuf != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     json_object_put(json);
                                     free(data);
                                     data = NULL;
                                 }
    ,ERR_OUT_OF_MEMORY, "Unable to allocate inbuf: Out of memory", ""
    );

    size = SHA256_from_string(data, inbuf);

    unsigned char* outbuf = calloc(size + EVP_MAX_BLOCK_LENGTH, sizeof(unsigned char));
    M_REQUIRE_ELSE_RUN_EXIT_CODE(outbuf != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     json_object_put(json);
                                     free(inbuf);
                                     inbuf = NULL;
                                     free(data);
                                     data = NULL;
                                 },
                                 ERR_OUT_OF_MEMORY,"Unable to allocate outbuf: Out of memory", "");

    size_t verif = 0;

    code = ckvs_client_crypt_value(&mymr, 0, inbuf, size, outbuf, &verif);

    free(inbuf);
    free(data);
    data = NULL;

    json_object_put(json);
    ckvs_rpc_close(&conn);

    M_REQUIRE(code == ERR_NONE, code, "Unable to decrypt the value", "");

    // Print the decrypted value
    pps_printf("%s", outbuf);

    free(outbuf);
    outbuf = NULL;


    return ERR_NONE;
}

int ckvs_client_set(const char *url, int optargc, char **optargv) {

    error_code code = nb_arguments_required(&optargc, 3);
    M_REQUIRE(code == ERR_NONE, code,"Wrong number of arguments", "" );

    // NULL pointer check
    code = non_null_checker(url, optargc, optargv);
    M_REQUIRE(code == ERR_NONE, code, "NULL pointer exception", "");

    char key[strlen(optargv[0]) + 1];
    strcpy(key, optargv[0]);
    char pwd[strlen(optargv[1]) + 1];
    strcpy(pwd, optargv[1]);

    char* valuefilename = optargv[2];

    size_t buffer_size;
    char* buffer;
    code = read_value_file_content(valuefilename, &buffer, &buffer_size);


    ////////////////////////////////
    // Compute the different keys //
    ///////////////////////////////


    ckvs_memrecord_t mymr;

    code = ckvs_client_encrypt_pwd(&mymr, key, pwd);
    M_REQUIRE(code == ERR_NONE, code, "could not compute the keys", "");

    // Our new C2 key initialized to 0
    ckvs_sha_t newc2;
    memset(&newc2, 0, sizeof(ckvs_sha_t)); // Not needed as we set each byte to a random value later

    // We generate a new C2
    M_REQUIRE(RAND_bytes(newc2.sha, SHA256_DIGEST_LENGTH) == 1, ERR_IO, "It was impossible to generate a new random C2 key", "");

    // We generate the Master key with the new c2
    code = ckvs_client_compute_masterkey(&mymr, &newc2);
    M_REQUIRE(code == ERR_NONE, code, "Impossible to compute the master key", "");


    //////////////////////
    // Encrypt the file //
    /////////////////////


    size_t inbuflen = buffer_size + 1; // + 1 for the null byte \0
    unsigned char* inbuf = calloc(inbuflen, sizeof(unsigned char));

    M_REQUIRE(inbuf != NULL, ERR_OUT_OF_MEMORY, "Unable to allocate inbuf: Out of memory", "");

    memcpy(inbuf, buffer, buffer_size);
    inbuf[inbuflen - 1] = '\0';

    size_t outbuflen = 0;
    unsigned char* outbuf = calloc(inbuflen + EVP_MAX_BLOCK_LENGTH, sizeof(unsigned char));

    free(buffer);
    buffer = NULL;

    M_REQUIRE_ELSE_RUN_EXIT_CODE(outbuf != NULL,
                                 {
                                     free(inbuf);
                                     inbuf = NULL;
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

                                 }
    ,code, "could not encrypt value", ""
    );


    ////////////////////////////////////////
    // Create connection with the server //
    //////////////////////////////////////


    ckvs_connection_t conn;
    code = ckvs_rpc_init(&conn, url);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(code == ERR_NONE,
                                 {
                                     free(outbuf);
                                     outbuf = NULL;

                                 }
    ,code, "Unable to initialize the connexion", ""
    );


    ////////////////
    // Create URL //
    ///////////////


    char* key_url = curl_easy_escape(conn.curl, key, 0);

    M_REQUIRE_ELSE_RUN_EXIT_CODE(key_url != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     free(outbuf);
                                     outbuf = NULL;

                                 }
    ,ERR_OUT_OF_MEMORY, "Unable to transform key into url format", ""
    );

    char auth_string[SHA256_PRINTED_STRLEN];
    SHA256_to_string(&mymr.auth_key, auth_string);

    char SET[strlen(key_url) + strlen(auth_string) + strlen("/set?name=data.json&offset=0&key=&auth_key=") + 1];

    code = sprintf(SET, "/set?name=data.json&offset=0&key=%s&auth_key=%s", key_url, auth_string);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(code >= 0,
                                 {
                                     ckvs_rpc_close(&conn);
                                     free(outbuf);
                                     curl_free(key_url);
                                 }
    , ERR_IO, "Unable to create GET string", ""
    );
    curl_free(key_url);

    /////////////////////////
    // Create JSON objects //
    ////////////////////////

    json_object *json = json_object_new_object();
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     free(outbuf);
                                 }
    , ERR_IO, "Unable to create Json object", ""
    );

    char c2_string[SHA256_PRINTED_STRLEN];
    SHA256_to_string(&newc2, c2_string);

    char* data_string = calloc(2*outbuflen + 1, sizeof(char));
    hex_encode(outbuf, outbuflen, data_string);

    free(outbuf);
    outbuf = NULL;


    M_REQUIRE_ELSE_RUN_EXIT_CODE(data_string != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     json_object_put(json);
                                 }
    , ERR_OUT_OF_MEMORY, "Unable to allocate data_string: Out of memory", ""
    );

    json_object* json_c2   = json_object_new_string(c2_string);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_c2 != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     free(data_string);
                                     data_string = NULL;
                                     json_object_put(json);
                                 }
    , ERR_OUT_OF_MEMORY, "Unable to create json_c2", ""
    );
    json_object* json_data = json_object_new_string(data_string);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_data != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     free(data_string);
                                     data_string = NULL;
                                     json_object_put(json);
                                 }
    , ERR_OUT_OF_MEMORY, "Unable to create json_data", ""
    );

    free(data_string);
    data_string = NULL;

    json_object_object_add(json, "c2",   json_c2);
    json_object_object_add(json, "data", json_data);

    const char* json_string = json_object_to_json_string(json);
    M_REQUIRE_ELSE_RUN_EXIT_CODE(json_string != NULL,
                                 {
                                     ckvs_rpc_close(&conn);
                                     json_object_put(json);
                                 }
    , ERR_IO, "Unable to convert json_object to json_string", ""
    );

    code = ckvs_post(&conn, SET, json_string);

    json_object_put(json);
    ckvs_rpc_close(&conn);

    return ERR_NONE;

}
