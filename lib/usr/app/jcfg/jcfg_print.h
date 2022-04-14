/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _JCFG_PRINT_H_
#define _JCFG_PRINT_H_

#include "jcfg.h"

/**
 * @file
 *
 * JSON-C configuration routines for printing object data.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Common print object routine
 *
 * @param hdr
 *   The common header pointer for all object.
 * @param val
 *   The object obj_value_t pointer to print
 */
void __print_object(jcfg_hdr_t *hdr, obj_value_t *val);

/**
 * Macros to print out the common object types jcfg_opt_t information
 */
#define __print_application __print_object
#define __print_default     __print_object
#define __print_option      __print_object
#define __print_user        __print_object

/**
 * Common print umem object routine
 *
 * @param hdr
 *   The common header pointer for all object.
 * @param val
 *   The object obj_value_t pointer to print
 */
void __print_umem(jcfg_hdr_t *hdr, obj_value_t *val);

/**
 * Common print lport object routine
 *
 * @param hdr
 *   The common header pointer for all object.
 * @param val
 *   The object obj_value_t pointer to print
 */
void __print_lport(jcfg_hdr_t *hdr, obj_value_t *val);

/**
 * Common print lgroup object routine
 *
 * @param hdr
 *   The common header pointer for all object.
 * @param val
 *   The object obj_value_t pointer to print
 */
void __print_lgroup(jcfg_hdr_t *hdr, obj_value_t *val);

/**
 * Common print thread object routine
 *
 * @param hdr
 *   The common header pointer for all object.
 * @param val
 *   The object obj_value_t pointer to print
 */
void __print_thread(jcfg_hdr_t *hdr, obj_value_t *val);

/**
 * Common print lport group object routine
 *
 * @param hdr
 *   The common header pointer for all object.
 * @param val
 *   The object obj_value_t pointer to print
 */
void __print_lport_group(jcfg_hdr_t *hdr, obj_value_t *val);

#ifdef __cplusplus
}
#endif

#endif /* _JCFG_PRINT_H_ */
