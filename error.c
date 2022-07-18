/**
 * @file error.c
 * @brief PPS (CS-212) error messages
 */

#include "error.h"

const char * const ERR_MESSAGES[] = {
    "", // no error
    "I/O Error",
    "(re|m|c)alloc failled",
    "Not enough arguments",
    "Too many arguments",
    "Invalid filename",
    "Invalid command",
    "Invalid argument",
    "Invalid max_files number",
    "Key not found",
    "No value",
    "Not implemented (yet?)",
    "Incorrect key/password",
    "Corrupt database file",
    "Timeout in network operation",
    "Protocol error",
    "no error (shall not be displayed)" // ERR_LAST
};

int non_null_checker(const char* filename, int optargc, char* optargv[]) {
    M_REQUIRE_NON_NULL(filename);
    for(int i = 0; i < optargc; i++) {
        M_REQUIRE_NON_NULL(optargv[i]);
    }
    return ERR_NONE;
}

int nb_arguments_required(const int* nb_arguments_given, const int nb_argument_expected) {
    M_REQUIRE(*nb_arguments_given >= nb_argument_expected, ERR_NOT_ENOUGH_ARGUMENTS, "Not enough arguments for get : %d arguments", *nb_arguments_given);
    M_REQUIRE(*nb_arguments_given <= nb_argument_expected, ERR_TOO_MANY_ARGUMENTS, "Too many arguments for get : %d arguments", *nb_arguments_given);

    return ERR_NONE;
}

