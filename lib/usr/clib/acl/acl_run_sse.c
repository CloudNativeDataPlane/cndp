/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2022 Intel Corporation
 */

#include "acl_run_sse.h"

#include "cne_branch_prediction.h"        // for likely

int
cne_acl_classify_sse(const struct cne_acl_ctx *ctx, const uint8_t **data, uint32_t *results,
                     uint32_t num, uint32_t categories)
{
    if (likely(num >= MAX_SEARCHES_SSE8))
        return search_sse_8(ctx, data, results, num, categories);
    else if (num >= MAX_SEARCHES_SSE4)
        return search_sse_4(ctx, data, results, num, categories);
    else
        return cne_acl_classify_scalar(ctx, data, results, num, categories);
}
