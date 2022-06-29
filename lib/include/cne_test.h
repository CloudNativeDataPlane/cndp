/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015 Cavium, Inc
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef _CNE_TEST_H_
#define _CNE_TEST_H_

#include <cne_log.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Before including cne_test.h file you can define
 * CNE_TEST_TRACE_FAILURE(_file, _line, _func) macro to better trace/debug test
 * failures. Mostly useful in development phase.
 */
#ifndef CNE_TEST_TRACE_FAILURE
#define CNE_TEST_TRACE_FAILURE(_file, _line, _func)
#endif

/**
 * Basic define for assertion of a condition used by other defines.
 */
#define CNE_TEST_ASSERT(cond, msg, ...)                                             \
    do {                                                                            \
        if (!(cond)) {                                                              \
            CNE_ERR("Test assert %s line %d failed: " msg "\n", __func__, __LINE__, \
                    ##__VA_ARGS__);                                                 \
            CNE_TEST_TRACE_FAILURE(__FILE__, __LINE__, __func__);                   \
            return -1;                                                              \
        }                                                                           \
    } while (0)

/**
 * Test for *a* and *b* to be equal or assertion is raised
 *
 * @param a
 *   The first value to test for equal, must be a scalar value
 * @param b
 *   The second value to test for equal, must be a scalar value
 * @param msg
 *   The message to display along with any values to be printed, using printf() like format.
 */
#define CNE_TEST_ASSERT_EQUAL(a, b, msg, ...) CNE_TEST_ASSERT(a == b, msg, ##__VA_ARGS__)

/**
 * Test for *a* and *b* to be not-equal or assertion is raised
 *
 * @param a
 *   The first value to test for not-equal, must be a scalar value
 * @param b
 *   The second value to test for not-equal, must be a scalar value
 * @param msg
 *   The message to display along with any values to be printed, using printf() like format.
 */
#define CNE_TEST_ASSERT_NOT_EQUAL(a, b, msg, ...) CNE_TEST_ASSERT(a != b, msg, ##__VA_ARGS__)

/**
 * Test *val* to be equal to zero or assertion is raised
 *
 * @param val
 *   Assert val is equal to zero.
 * @param msg
 *   The message to display along with any values to be printed, using printf() like format.
 */
#define CNE_TEST_ASSERT_SUCCESS(val, msg, ...) CNE_TEST_ASSERT(val == 0, msg, ##__VA_ARGS__)

/**
 * Test *val* to be not-equal to zero or assertion is raised
 *
 * @param val
 *   Assert val is not-equal to zero.
 * @param msg
 *   The message to display along with any values to be printed, using printf() like format.
 */
#define CNE_TEST_ASSERT_FAIL(val, msg, ...) CNE_TEST_ASSERT(val != 0, msg, ##__VA_ARGS__)

/**
 * Test *val* to be equal to NULL or assertion is raised
 *
 * @param val
 *   Assert val is equal to NULL.
 * @param msg
 *   The message to display along with any values to be printed, using printf() like format.
 */
#define CNE_TEST_ASSERT_NULL(val, msg, ...) CNE_TEST_ASSERT(val == NULL, msg, ##__VA_ARGS__)

/**
 * Test *val* to be not-equal to NULL or assertion is raised
 *
 * @param val
 *   Assert val is not-equal to NULL.
 * @param msg
 *   The message to display along with any values to be printed, using printf() like format.
 */
#define CNE_TEST_ASSERT_NOT_NULL(val, msg, ...) CNE_TEST_ASSERT(val != NULL, msg, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* _CNE_TEST_H_ */
