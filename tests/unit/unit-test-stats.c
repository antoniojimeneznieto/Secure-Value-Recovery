/**
 * @file unit-test-stats.c
 * @brief Unit tests for the local 'stats' command
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
#include <stdio.h>
#include <string.h>

#include "tests.h"
#include "error.h"
#include "ckvs.h"
#include "ckvs_local.h"

#include "ckvs_test_util.h"

#define NON_EXISTING_CKVS "./does_not_exist.ckvs"


IMPLEMENT_MUTED_PPS_PRINTF

// ======================================================================
START_TEST(stats_invalid_filename)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ck_assert_int_eq(ckvs_local_stats(NULL), ERR_INVALID_ARGUMENT);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(stats_non_existing_file)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    ck_assert_int_eq(ckvs_local_stats(NON_EXISTING_CKVS), ERR_IO);

#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST


// ======================================================================
START_TEST(stats_invalid_header_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(header, "CS212 Crypt", 1, 64, 16, 0); // invalid header_str
    ckvs_entry_t* entries = calloc(header.table_size, sizeof(ckvs_entry_t));
    ck_assert_ptr_nonnull(entries);
    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &header, entries), 0);
    free(entries);

    ck_assert_int_eq(ckvs_local_stats(DUMMY_NAME), ERR_CORRUPT_STORE);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(stats_invalid_header_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(header, "CS212 CryptKVS", 2, 64, 16, 0); // version != 1
    ckvs_entry_t* entries = calloc(header.table_size, sizeof(ckvs_entry_t));
    ck_assert_ptr_nonnull(entries);
    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &header, entries), 0);
    free(entries);

    ck_assert_int_eq(ckvs_local_stats(DUMMY_NAME), ERR_CORRUPT_STORE);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(stats_invalid_header_3)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(header, "CS212 CryptKVS", 1, 66, 10, 0); // not a power of 2 (and != 64 for weeks < 8)

    ckvs_entry_t* entries = calloc(header.table_size, sizeof(ckvs_entry_t));
    ck_assert_ptr_nonnull(entries);

    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &header, entries), 0);
    free(entries);

    ck_assert_int_eq(ckvs_local_stats(DUMMY_NAME), ERR_CORRUPT_STORE);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(stats_invalid_header_4)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(header, "CS212 CryptKVS", 1, 64, 10, 0);

    ckvs_entry_t* entries = calloc(63, sizeof(ckvs_entry_t)); // do not write enough entries
    ck_assert_ptr_nonnull(entries);

    FILE* f = fopen(DUMMY_NAME, "wb");
    ck_assert_ptr_nonnull(f);

    ck_assert_int_eq(fwrite(&header, sizeof(ckvs_header_t), 1, f), 1);
    ck_assert_int_eq(fwrite(entries, sizeof(ckvs_entry_t), 63, f), 63);
    fclose(f);
    free(entries);

    ck_assert_int_eq(ckvs_local_stats(DUMMY_NAME), ERR_IO);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST



// ======================================================================
START_TEST(stats_valid_header_1)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif
    // setup invalid dummy file
    init_header(header, "CS212 CryptKVS-MK.II", 1, 64, 20, 0);

    ckvs_entry_t* entries = calloc(header.table_size, sizeof(ckvs_entry_t));
    ck_assert_ptr_nonnull(entries);

    ck_assert_int_eq(create_file_and_dump_db(DUMMY_NAME, &header, entries), 0);
    free(entries);

    ck_assert_int_eq(ckvs_local_stats(DUMMY_NAME), ERR_NONE);

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
START_TEST(stats_valid_header_2)
{
// ------------------------------------------------------------
#ifdef WITH_PRINT
    printf("=== %s:\n", __func__);
#endif

    // delete the dummy file
    remove(DUMMY_NAME);
#ifdef WITH_PRINT
    printf("=== END of %s\n", __func__);
#endif
}
END_TEST

// ======================================================================
Suite* stats_test_suite()
{
#ifdef WITH_RANDOM
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
    srand(time(NULL) ^ getpid() ^ pthread_self());
#pragma GCC diagnostic pop
#endif // WITH_RANDOM
    
    Suite* s = suite_create("Tests of the 'stats' command (may not be exhaustive!)");

    Add_Case(s, tc1, "Stats tests");
    tcase_add_test(tc1, stats_invalid_filename);
    tcase_add_test(tc1, stats_non_existing_file);
    tcase_add_test(tc1, stats_invalid_header_1);
    tcase_add_test(tc1, stats_invalid_header_2);
    tcase_add_test(tc1, stats_invalid_header_3);
    tcase_add_test(tc1, stats_invalid_header_4);

    tcase_add_test(tc1, stats_valid_header_1);

    return s;
}

TEST_SUITE(stats_test_suite)