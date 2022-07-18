#pragma once

/**
 * @file error.h
 * @brief Error codes for PPS course (CS-212)
 *
 * @author E. Bugnion, J.-C. Chappelier, V. Rousset
 * @date 2016-2021
 */
#include <stdio.h> // for fprintf
#include <string.h> // strerror()
#include <errno.h>  // errno

#ifdef __cplusplus
extern "C" {
#endif

// ======================================================================
/**
 * @brief internal error codes.
 *
 */
typedef enum {
    ERR_CLANG_TYPE_FIX = -1, // this stupid value is to fix type to be int instead of unsigned on some compilers (e.g. clang version 8.0)
    ERR_NONE = 0, // no error

    ERR_IO,
    ERR_OUT_OF_MEMORY,
    ERR_NOT_ENOUGH_ARGUMENTS,
    ERR_TOO_MANY_ARGUMENTS,
    ERR_INVALID_FILENAME,
    ERR_INVALID_COMMAND,
    ERR_INVALID_ARGUMENT,
    ERR_MAX_FILES,
    ERR_KEY_NOT_FOUND,
    ERR_NO_VALUE,
    NOT_IMPLEMENTED,
    ERR_DUPLICATE_ID,
    ERR_CORRUPT_STORE,
    ERR_TIMEOUT,
    ERR_PROTOCOL,
    ERR_NB_ERR // not an actual error but to have the total number of errors
} error_code;

// ======================================================================
/*
 * Helpers (macros)
 */

// ----------------------------------------------------------------------

#ifdef DEBUG
// dirty trick, waiting for N2023 (www.open-std.org/jtc1/sc22/wg14/www/docs/n2023.pdf) to be implemented...
#define debug_printf_core(fmt, ...)                                       \
        do { fprintf(stderr, "DEBUG %s:%d:%s(): " fmt "%s\n", __FILE__, __LINE__, __func__, __VA_ARGS__); } while (0)
#else
#define debug_printf_core(fmt, ...) \
    do {} while(0)
#endif
/**
 * @brief debug_printf macro is useful to print message in DEBUG mode only.
 */
#define debug_printf(...) debug_printf_core(__VA_ARGS__, "")

// ----------------------------------------------------------------------
/**
 * @brief M_EXIT macro is useful to return an error code from a function with a debug message.
 *        Example usage:
 *           M_EXIT(ERR_INVALID_ARGUMENT, "unable to do something decent with value %lu", i);
 */
#define M_EXIT(error_code, fmt, ...)  \
    do { \
        debug_printf(fmt, __VA_ARGS__); \
        return error_code; \
    } while(0)

// ----------------------------------------------------------------------
/**
 * @brief M_REQUIRE macro is similar to M_EXIT, but exits only when the
 *        provided test is false (thus "require").
 *        Example usage:
 *            M_REQUIRE(i <= 3, ERR_INVALID_ARGUMENT, "input value (%lu) is too high (> 3)", i);
 */
#define M_REQUIRE(test, error_code, fmt, ...)   \
    do { \
        if (!(test)) { \
             M_EXIT(error_code, fmt, __VA_ARGS__); \
        } \
    } while(0)

// ----------------------------------------------------------------------
/**
 * @brief M_REQUIRE_NON_NULL macro is useful for requiring non-NULL arguments.
 *        Example usage:
 *            int my_favorite_function(struct whatever* key)
 *            {
 *                M_REQUIRE_NON_NULL(key);
 */
#define M_REQUIRE_NON_NULL(arg) \
    M_REQUIRE((arg) != NULL, ERR_INVALID_ARGUMENT, "parameter %s is NULL", #arg)

// ----------------------------------------------------------------------
/**
 * @brief M_REQUIRE_ELSE_CLOSE_CKVS macro is similar to M_REQUIRE, but closes the ckvs and exits only when the
 *        provided test is false (thus "require").
 *        Example usage:
 *            M_REQUIRE_ELSE_CLOSE(i <= 3, ckvs, ERR_IO, "input value (%lu) is too high (> 3)", i);
 */
#define M_REQUIRE_ELSE_RUN_EXIT_CODE(test, exit_code, error_code, fmt, ...)   \
    do { \
        if (!(test)) { \
             exit_code \
             M_EXIT(error_code, fmt, __VA_ARGS__); \
        } \
    } while(0)


// ----------------------------------------------------------------------
/**
 * @brief M_REQUIRE_ELSE_CLOSE_CKVS macro is similar to M_REQUIRE, but closes the ckvs and exits only when the
 *        provided test is false (thus "require").
 *        Example usage:
 *            M_REQUIRE_ELSE_CLOSE(i <= 3, ckvs, ERR_IO, "input value (%lu) is too high (> 3)", i);
 */
#define M_REQUIRE_ELSE_CLOSE_CKVS(test, ckvs, error_code, fmt, ...)   \
    do { \
        if (!(test)) { \
             ckvs_close(ckvs); \
             M_EXIT(error_code, fmt, __VA_ARGS__); \
        } \
    } while(0)

// ======================================================================
/**
* @brief internal error messages. defined in error.c
*
*/
extern
const char* const ERR_MESSAGES[];

/**
 * @brief Verifies that the arguments are non-NULL
 *
 * @param filename (const char*) the path to be verified to be non-NULL
 * @param optargc number of elements in @optargv to verify
 * @param optargv array containing the arguments to be verified
 * @return int, error code
 */
int non_null_checker(const char* filename, int optargc, char* optargv[]);

/**
 * @brief Verifies that the number of arguments is correct
 *
 * @param nb_arguments number of arguments that contained
 * @param nb_arguments number of arguments that should be contained
 * @return int, error code
 */
int nb_arguments_required(const int* nb_arguments_given, const int nb_argument_expected);

#ifdef __cplusplus
}
#endif
