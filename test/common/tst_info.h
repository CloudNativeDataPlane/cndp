/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef _TESTING_INFO_H_
#define _TESTING_INFO_H_

#include <stdbool.h>        // for true, bool, false
#include <stddef.h>         // for NULL
#include <stdint.h>         // for uint32_t
/**
 * @file
 * CNE Testing Info
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <cne_log.h>

#define TST_PASSED true  /**< used for tst_end() when a test passes */
#define TST_FAILED false /**< used for tst_end() when a test fails */

typedef struct {
    char *name; /**< Name of the test cne_strdup'ed */
    int lid;    /**< lcore id */
    int sid;    /**< socket id */
} tst_info_t;

/**
 * Print a summary of test results
 *
 * @return
 *   number of test failures
 */
uint32_t tst_summary(void);

/**
 * Start a test
 *
 * Also print out the socket and lcore ids plus the test's name. This function calls
 * abort() if memory cannot be allocated. Use the tst_end() function to free memory
 * allocated by this function.
 *
 * @param name
 *   The name of the test
 * @return
 *   pointer to tst_info structure
 */
tst_info_t *tst_start(const char *name);

/**
 * End a test
 *
 * This function records the pass/fail status and frees the tst_info structure.
 *
 * @param tst
 *   pointer to tst_info structure
 * @param passed
 *   TST_PASSED if the test passed or TST_FAILED if the test failed
 */
void tst_end(tst_info_t *tst, bool passed);

/**
 * The following functions are used for colorful logging
 *
 * Also prepend the message with one of PASS/FAIL/INFO strings.
 *
 * @param fmt
 *   printf like format
 * @param ...
 *   variable length arguments
 */
void tst_ok(const char *fmt, ...) __attribute__((__format__(__printf__, 1, 0)));
void tst_error(const char *fmt, ...) __attribute__((__format__(__printf__, 1, 0)));
void tst_info(const char *fmt, ...) __attribute__((__format__(__printf__, 1, 0)));

#define TST_ASSERT_RETURN(cond, msg, ...)                                                   \
    do {                                                                                    \
        if (!(cond)) {                                                                      \
            cne_printf("[yellow]Test assert %s line %d [red]failed[]: " msg "\n", __func__, \
                       __LINE__, ##__VA_ARGS__);                                            \
            return;                                                                         \
        }                                                                                   \
    } while (0)

#define TST_ASSERT_GOTO(cond, msg, lbl, ...)                                                \
    do {                                                                                    \
        if (!(cond)) {                                                                      \
            cne_printf("[yellow]Test assert %s line %d [red]failed[]: " msg "\n", __func__, \
                       __LINE__, ##__VA_ARGS__);                                            \
            goto lbl;                                                                       \
        }                                                                                   \
    } while (0)

#define TST_ASSERT(cond, msg, ...)                                                          \
    do {                                                                                    \
        if (!(cond)) {                                                                      \
            cne_printf("[yellow]Test assert %s line %d [red]failed[]: " msg "\n", __func__, \
                       __LINE__, ##__VA_ARGS__);                                            \
            return -1;                                                                      \
        }                                                                                   \
    } while (0)

#define TST_ASSERT_AND_CLEANUP(cond, msg, _function, _arg, ...)                             \
    do {                                                                                    \
        if (!(cond)) {                                                                      \
            cne_printf("[yellow]Test assert %s line %d [red]failed[]: " msg "\n", __func__, \
                       __LINE__, ##__VA_ARGS__);                                            \
            _function(_arg);                                                                \
            return -1;                                                                      \
        }                                                                                   \
    } while (0)

#define TST_ASSERT_EQUAL(a, b, msg, ...) TST_ASSERT(a == b, msg, ##__VA_ARGS__)

#define TST_ASSERT_NOT_EQUAL(a, b, msg, ...) TST_ASSERT(a != b, msg, ##__VA_ARGS__)

#define TST_ASSERT_SUCCESS(val, msg, ...) TST_ASSERT(val == 0, msg, ##__VA_ARGS__)

#define TST_ASSERT_FAIL(val, msg, ...) TST_ASSERT(val != 0, msg, ##__VA_ARGS__)

#define TST_ASSERT_NULL(val, msg, ...) TST_ASSERT(val == NULL, msg, ##__VA_ARGS__)

#define TST_ASSERT_NOT_NULL(val, msg, ...) TST_ASSERT(val != NULL, msg, ##__VA_ARGS__)

#define TST_ASSERT_EQUAL_AND_CLEANUP(a, b, msg, _function, _arg, ...) \
    TST_ASSERT_AND_CLEANUP(a == b, msg, _function, _arg, ##__VA_ARGS__)

#define TST_ASSERT_NOT_EQUAL_AND_CLEANUP(a, b, msg, _function, _arg, ...) \
    TST_ASSERT_AND_CLEANUP(a != b, msg, _function, _arg, ##__VA_ARGS__)

#define TST_ASSERT_SUCCESS_AND_CLEANUP(val, msg, _function, _arg, ...) \
    TST_ASSERT_AND_CLEANUP(val == 0, msg, _function, _arg, ##__VA_ARGS__)

#define TST_ASSERT_FAIL_AND_CLEANUP(val, msg, _function, _arg, ...) \
    TST_ASSERT_AND_CLEANUP(val != 0, msg, _function, _arg, ##__VA_ARGS__)

#define TST_ASSERT_NULL_AND_CLEANUP(val, msg, _function, _arg, ...) \
    TST_ASSERT_AND_CLEANUP(val == NULL, msg, _function, _arg, ##__VA_ARGS__)

#define TST_ASSERT_NOT_NULL_AND_CLEANUP(val, msg, _function, _arg, ...) \
    TST_ASSERT_AND_CLEANUP(val != NULL, msg, _function, _arg, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* _TESTING_INFO_H_ */
