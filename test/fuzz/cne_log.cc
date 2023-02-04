/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Intel Corporation
 */

#include <cne_log.h>

/* Prototype required to fix "no previous prototype for function" error */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data_, size_t size)
{
    char *data;

    /* Need at least one byte for null terminator */
    if (size < 1)
        return 0;
    /* Create null-terminated string from input data */
    data = (char *)calloc(size + 1, sizeof(char));
    if (!data)
        return 0;
    strncpy(data, (const char *)data_, size);

    /* Replacing '%' with another character. This is needed to
     *  avoid SEGV on unknown address in Address Sanitizer. */
    for (size_t i = 0; i < size; i++) {
        if (data[i] == '%')
            data[i] = 'f';
    }
    cne_log(size % CNE_LOG_LAST, (const char *)data, 0, "%s\n", __func__);
    free(data);
    return 0;
}
