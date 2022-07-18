#pragma once

/**
 * @file util.h
 * @brief PPS (CS-212) Tool macros
 *
 * @author Jean-Cédric Chappelier
 * @date 2017-2021
 */

#include <assert.h> // see TO_BE_IMPLEMENTED

/**
 * @brief tag a variable as POTENTIALLY unused, to avoid compiler warnings
 */
#define _unused __attribute__((unused))

/**
 * @brief useful for partial implementation
 */
#define TO_BE_IMPLEMENTED() \
    do { fprintf(stderr, "TO_BE_IMPLEMENTED!\n"); assert(0); } while (0)

/**
 * @brief useful to free pointers to const without warning. Use with care!
 */
#define free_const_ptr(X) free((void*)X)

/**
 * @brief useful to have C99 (!) %zu to compile in Windows
 */
#if defined _WIN32  || defined _WIN64
#define SIZE_T_FMT "%u"
#else
#define SIZE_T_FMT "%zu"
#endif

/**
 * @brief useful to specify a length defined by a macro for format strings
 */
#define STR(x) #x
/**
 * @brief useful to specify a length defined by a macro for format strings
 */
#define STR_LENGTH_FMT(x) "%." STR(x) "s"
