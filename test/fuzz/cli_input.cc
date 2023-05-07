/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2023 Intel Corporation
 */

#include <cne_common.h>
#include <cli_input.h>

/* Prototype required to fix "no previous prototype for function" error */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    int silent = 1;

    if (cli_create_with_defaults(NULL))
        return 1;

    /* cast is to fix "cast drops const qualifier" error */
    cli_input((char *)(uintptr_t)data, size, silent);

    cli_destroy();
    return 0;
}
