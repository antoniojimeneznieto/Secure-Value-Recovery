/**
 * @file unit-test-util.c
 * @brief Unit tests for the ckvs_util.h functions
 *
 * @author A. Clergeot, EPFL
 * @date 2021
 */

#ifdef WITH_RANDOM
// for thread-safe randomization (useless here, but kept in case we'd like to have random generation inside the tests)
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#endif

#include <check.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>

#include "tests.h"
#include "error.h"
#include "ckvs_utils.h"

#include "ckvs_test_util.h"

static char output_buffer[1024] = { '\0' };

// ------------------------------------------------------------
int pps_printf(const char* __restrict__ format, ...) {
    va_list argp;
    va_start(argp, format);

    int written = vsnprintf(output_buffer, sizeof(output_buffer) - 1, format, argp);
    output_buffer[written >= 0 ? written : 0] = '\0';

    va_end(argp);
    return written;
}

// ======================================================================
START_TEST(SHA256_to_string_NULL)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ckvs_sha_t sha;
    char buf[SHA256_PRINTED_STRLEN];

    // should not segfault
    SHA256_to_string(&sha, NULL);
    SHA256_to_string(NULL, buf);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(SHA256_to_string_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ckvs_sha_t sha;
    for (size_t i = 0 ; i < SHA256_DIGEST_LENGTH ; ++i)
        sha.sha[i] = 0x80 + i * 3;
    const char* expected = "808386898c8f9295989b9ea1a4a7aaadb0b3b6b9bcbfc2c5c8cbced1d4d7dadd";

    char buf[SHA256_PRINTED_STRLEN];
    SHA256_to_string(&sha, buf);

    ck_assert_str_eq(buf, expected);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(print_SHA_null)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ckvs_sha_t sha;

    // should not segfault
    print_SHA("Prefix", NULL);
    print_SHA(NULL, &sha);
    print_SHA(NULL, NULL);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(print_SHA_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ckvs_sha_t sha;
    for (size_t i = 0 ; i < SHA256_DIGEST_LENGTH ; ++i)
        sha.sha[i] = i;
    
    const char* expected = "Long prefix: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n";
    print_SHA("Long prefix", &sha);

    ck_assert_str_eq(expected, output_buffer);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(print_SHA_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ckvs_sha_t sha = { { 0 } };    
    const char* const expected = "sha  : 0000000000000000000000000000000000000000000000000000000000000000\n";
    print_SHA("sha", &sha);

    ck_assert_str_eq(expected, output_buffer);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST


// ======================================================================
Suite* util_test_suite()
{
#ifdef WITH_RANDOM
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
    srand(time(NULL) ^ getpid() ^ pthread_self());
#pragma GCC diagnostic pop
#endif // WITH_RANDOM
    
    Suite* s = suite_create("Tests for hexadecimal convertion operations (may not be exhaustive!)");

    Add_Case(s, tc1, "util tests");
    tcase_add_test(tc1, SHA256_to_string_NULL);
    tcase_add_test(tc1, SHA256_to_string_1);
    tcase_add_test(tc1, print_SHA_null);
    tcase_add_test(tc1, print_SHA_1);
    tcase_add_test(tc1, print_SHA_2);

    return s;
}

TEST_SUITE(util_test_suite)
