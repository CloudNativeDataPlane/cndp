/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2025 Intel Corporation
 */

#include <cne_common.h>
#include <uds.h>

/* Prototype required to fix "no previous prototype for function" error */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data_, size_t size)
{
    const char *err_str = NULL;
    uds_info_t *info;
    char *data;

    /* Need at least one byte for null terminator */
    if (size < 1)
        return 0;

    /* Truncate to 256 characters since a file is created */
    if (size > 256)
        size = 256;

    /* Copy old data to new data, and add null-terminator */
    data = (char *)malloc(size);
    if (!data)
        return 0;
    memcpy(data, data_, size);
    data[size - 1] = '\0';

    info = uds_create("./deleteme", (const char *)data, &err_str, NULL);
    /* there is a race between when the listening thread is created and when the
     * uds info context can be destroyed. Avoid it by sleeping a bit here.
     */
    usleep(1000);
    if (info)
        uds_destroy(info);
    free(data);
    return 0;
}
