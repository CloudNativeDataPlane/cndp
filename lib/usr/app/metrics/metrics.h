/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2022 Intel Corporation
 */

/**
 * @file
 *
 * Metrics-related utility functions
 */

#ifndef _METRICS_H_
#define _METRICS_H_

#include <stdint.h>

#include <cne_common.h>        // for CNDP_API
#include <cne_lport.h>
#include <uds.h>        // for uds_client_t, uds_info_t

#ifdef __cplusplus
extern "C" {
#endif

typedef uds_info_t metrics_info_t;
typedef uds_client_t metrics_client_t;

/* callback returns json data in buffer, up to buf_len long.
 * returns length of buffer used on success, negative on error.
 */
typedef int (*metrics_cb)(metrics_client_t *client, const char *cmd, const char *params);

/**
 * Register a new command to the metrics interface
 *
 * @param cmd
 *   The command string including the '/' e.g. '/pktdev:stats'
 * @param fn
 *   The function to callback for this command
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int metrics_register(const char *cmd, metrics_cb fn);

/**
 * Initialize metrics library.
 *
 * @param priv_
 *   Pointer to metrics command group private data.
 * @return
 *   0 on success, -1 on error with errno indicating reason for failure
 */
CNDP_API int metrics_init(void *priv_);

/**
 * Remove all registered metrics commands.
 *
 * @return
 *   0 on success, -1 on error with errno indicating reason for failure.
 */
CNDP_API int metrics_destroy(void);

/**
 * A snprintf() like routine to add text or data to the output buffer.
 *
 * @param c
 *   The client pointer that holds the buffer to append the text data.
 * @param fmt
 *   The snprintf() like format string with variable arguments
 * @param ...
 *   Arguments for the format string to use
 * @return
 *   The number of bytes appended to the data buffer.
 */
#define metrics_append(c, fmt, ...)                                      \
    do {                                                                 \
        uds_append((uds_client_t *)c, (const char *)fmt, ##__VA_ARGS__); \
    } while (0)

/**
 * Return the command string pointer
 *
 * @param client
 *   The client structure pointer
 * @return
 *   NULL if not defined or the string pointer.
 */
CNDP_API const char *metrics_cmd(metrics_client_t *client);

/**
 * Return the params string pointer
 *
 * @param client
 *   The client structure pointer
 * @return
 *   NULL if not defined or the string pointer.
 */
CNDP_API const char *metrics_params(metrics_client_t *client);

/**
 * Add the standard lport statistics to the metrics buffer
 *
 * @param c
 *   The metric_client_t structure pointer
 * @param name
 *   The name of the lport as a prefix to the stats names.
 * @param s
 *   The lport_stats_t structure pointer
 * @return
 *   -1 on error, 0 on success
 */
CNDP_API int metrics_port_stats(metrics_client_t *c, char *name, lport_stats_t *s);

#ifdef __cplusplus
}
#endif

#endif /* _METRICS_H_ */
