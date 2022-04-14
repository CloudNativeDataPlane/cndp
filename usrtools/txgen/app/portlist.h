/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

/**
 * @file
 *
 * String-related utility function for parsing lport mask.
 */

#ifndef __PORTLIST_H_
#define __PORTLIST_H_

#include <stdint.h>        // for uint64_t
#include <sys/types.h>
#include <string.h>
#include <stdio.h>        // for FILE

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t portlist_t;

/**
 * Parse a portlist string into a mask or bitmap value.
 *
 * @param str
 *   String to parse
 * @param portlist
 *   Pointer to uint64_t value for returned bitmap
 * @return
 *   -1 on error or 0 on success.
 */
int portlist_parse(const char *str, portlist_t *portlist);

/**
 * Parse a portmasl string into a mask or bitmap value.
 *
 * @param str
 *   String to parse
 * @param portlist
 *   Pointer to uint64_t value for returned bitmap
 * @return
 *   -1 on error or 0 on success.
 */
int portmask_parse(const char *str, portlist_t *portmask);

char *portlist_string(uint64_t portlist, char *buf, int len);
char *portlist_print(FILE *f, uint64_t portlist, char *buf, int len);

#ifdef __cplusplus
}
#endif

#endif /* __PORTLIST_H_ */
