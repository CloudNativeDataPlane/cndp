/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2022 Intel Corporation
 */

#include <bsd/string.h>        // for strlcpy
#include <errno.h>             // for EINVAL, ENOMEM, errno
#include <inttypes.h>          // for PRIu32, PRId32
#include <stdio.h>             // for snprintf
#include <stdlib.h>            // for free, calloc
#include <string.h>            // for memcpy

#include "cne_acl.h"
#include "acl.h"                     // for cne_acl_ctx, cne_acl_classify_scalar
#include "cne_cpuflags.h"            // for cne_cpu_get_flag_enabled, CNE_CPUFLAG_...
#include "cne_log.h"                 // for CNE_LOG_ERR, CNE_ERR_GOTO, CNE_ERR_RET...
#include "cne_build_config.h"        // for CNE_ARCH_X86
#include "cne_stdio.h"               // for cne_printf

#ifndef CC_AVX512_SUPPORT
/*
 * If the compiler doesn't support AVX512 instructions,
 * then the dummy one would be used instead for AVX2 classify method.
 */
int
cne_acl_classify_avx512x16(__cne_unused const struct cne_acl_ctx *ctx,
                           __cne_unused const uint8_t **data, __cne_unused uint32_t *results,
                           __cne_unused uint32_t num, __cne_unused uint32_t categories)
{
    return -ENOTSUP;
}

int
cne_acl_classify_avx512x32(__cne_unused const struct cne_acl_ctx *ctx,
                           __cne_unused const uint8_t **data, __cne_unused uint32_t *results,
                           __cne_unused uint32_t num, __cne_unused uint32_t categories)
{
    return -ENOTSUP;
}

#endif

#ifndef CC_AVX2_SUPPORT
/*
 * If the compiler doesn't support AVX2 instructions,
 * then the dummy one would be used instead for AVX2 classify method.
 */
int
cne_acl_classify_avx2(__cne_unused const struct cne_acl_ctx *ctx, __cne_unused const uint8_t **data,
                      __cne_unused uint32_t *results, __cne_unused uint32_t num,
                      __cne_unused uint32_t categories)
{
    return -ENOTSUP;
}
#endif

#ifndef CNE_ARCH_X86
int
cne_acl_classify_sse(__cne_unused const struct cne_acl_ctx *ctx, __cne_unused const uint8_t **data,
                     __cne_unused uint32_t *results, __cne_unused uint32_t num,
                     __cne_unused uint32_t categories)
{
    return -ENOTSUP;
}
#endif

static const cne_acl_classify_t classify_fns[] = {
    [CNE_ACL_CLASSIFY_DEFAULT]   = cne_acl_classify_scalar,
    [CNE_ACL_CLASSIFY_SCALAR]    = cne_acl_classify_scalar,
    [CNE_ACL_CLASSIFY_SSE]       = cne_acl_classify_sse,
    [CNE_ACL_CLASSIFY_AVX2]      = cne_acl_classify_avx2,
    [CNE_ACL_CLASSIFY_AVX512X16] = cne_acl_classify_avx512x16,
    [CNE_ACL_CLASSIFY_AVX512X32] = cne_acl_classify_avx512x32,
};

/* by default, use always available scalar code path. */
static enum cne_acl_classify_alg cne_acl_default_classify = CNE_ACL_CLASSIFY_SCALAR;

static void
cne_acl_set_default_classify(enum cne_acl_classify_alg alg)
{
    cne_acl_default_classify = alg;
}

extern int
cne_acl_set_ctx_classify(struct cne_acl_ctx *ctx, enum cne_acl_classify_alg alg)
{
    if (ctx == NULL || (uint32_t)alg >= CNE_DIM(classify_fns))
        return -EINVAL;

    ctx->alg = alg;
    return 0;
}

/*
 * Select highest available classify method as default one.
 * Note that CLASSIFY_AVX2 should be set as a default only
 * if both conditions are met:
 * at build time compiler supports AVX2 and target cpu supports AVX2.
 */
CNE_INIT(cne_acl_init)
{
    enum cne_acl_classify_alg alg = CNE_ACL_CLASSIFY_DEFAULT;

#ifdef CC_AVX2_SUPPORT
    if (cne_cpu_get_flag_enabled(CNE_CPUFLAG_AVX2))
        alg = CNE_ACL_CLASSIFY_AVX2;
    else if (cne_cpu_get_flag_enabled(CNE_CPUFLAG_SSE4_1))
#else
    if (cne_cpu_get_flag_enabled(CNE_CPUFLAG_SSE4_1))
#endif
        alg = CNE_ACL_CLASSIFY_SSE;

    cne_acl_set_default_classify(alg);
}

int
cne_acl_classify_alg(const struct cne_acl_ctx *ctx, const uint8_t **data, uint32_t *results,
                     uint32_t num, uint32_t categories, enum cne_acl_classify_alg alg)
{
    if (categories != 1 && ((CNE_ACL_RESULTS_MULTIPLIER - 1) & categories) != 0)
        return -EINVAL;

    return classify_fns[alg](ctx, data, results, num, categories);
}

int
cne_acl_classify(const struct cne_acl_ctx *ctx, const uint8_t **data, uint32_t *results,
                 uint32_t num, uint32_t categories)
{
    return cne_acl_classify_alg(ctx, data, results, num, categories, ctx->alg);
}

void
cne_acl_free(struct cne_acl_ctx *ctx)
{
    if (ctx == NULL)
        return;

    free(ctx->mem);
    free(ctx);
}

struct cne_acl_ctx *
cne_acl_create(const struct cne_acl_param *param)
{
    size_t sz;
    struct cne_acl_ctx *ctx;
    char name[sizeof(ctx->name)];

    /* check that input parameters are valid. */
    if (param == NULL || param->name == NULL) {
        errno = EINVAL;
        return NULL;
    }

    snprintf(name, sizeof(name), "ACL_%s", param->name);

    /* calculate amount of memory required for pattern set. */
    sz = sizeof(*ctx) + param->max_rule_num * param->rule_size;

    ctx = calloc(1, sz);

    if (ctx == NULL)
        CNE_ERR_GOTO(exit, "allocation of %zu bytes for %s failed\n", sz, name);

    /* init new allocated context. */
    ctx->rules     = ctx + 1;
    ctx->max_rules = param->max_rule_num;
    ctx->rule_sz   = param->rule_size;
    ctx->alg       = cne_acl_default_classify;
    strlcpy(ctx->name, param->name, sizeof(ctx->name));

exit:
    return ctx;
}

static int
acl_add_rules(struct cne_acl_ctx *ctx, const void *rules, uint32_t num)
{
    uint8_t *pos;

    if (num + ctx->num_rules > ctx->max_rules)
        return -ENOMEM;

    pos = ctx->rules;
    pos += ctx->rule_sz * ctx->num_rules;
    memcpy(pos, rules, num * ctx->rule_sz);
    ctx->num_rules += num;

    return 0;
}

static int
acl_check_rule(const struct cne_acl_rule_data *rd)
{
    if ((CNE_LEN2MASK(CNE_ACL_MAX_CATEGORIES, typeof(rd->category_mask)) & rd->category_mask) ==
            0 ||
        rd->priority > CNE_ACL_MAX_PRIORITY || rd->priority < CNE_ACL_MIN_PRIORITY)
        return -EINVAL;
    return 0;
}

int
cne_acl_add_rules(struct cne_acl_ctx *ctx, const struct cne_acl_rule *rules, uint32_t num)
{
    const struct cne_acl_rule *rv;
    uint32_t i;
    int32_t rc;

    if (ctx == NULL || rules == NULL || 0 == ctx->rule_sz)
        return -EINVAL;

    for (i = 0; i != num; i++) {
        rv = (const struct cne_acl_rule *)((uintptr_t)rules + i * ctx->rule_sz);
        rc = acl_check_rule(&rv->data);
        if (rc != 0)
            CNE_ERR_RET_VAL(rc, "%s(%s): rule #%u is invalid\n", __func__, ctx->name, i + 1);
    }

    return acl_add_rules(ctx, rules, num);
}

/*
 * Reset all rules.
 * Note that RT structures are not affected.
 */
void
cne_acl_reset_rules(struct cne_acl_ctx *ctx)
{
    if (ctx != NULL)
        ctx->num_rules = 0;
}

/*
 * Set ACL algorithm.
 */
void
cne_acl_set_algo(struct cne_acl_ctx *ctx, enum cne_acl_classify_alg algo)
{
    if (ctx != NULL)
        ctx->alg = algo;
}

/*
 * Reset all rules and destroys RT structures.
 */
void
cne_acl_reset(struct cne_acl_ctx *ctx)
{
    if (ctx != NULL) {
        cne_acl_reset_rules(ctx);
        cne_acl_build(ctx, &ctx->config);
    }
}

/*
 * Dump ACL context to the stdout.
 */
void
cne_acl_dump(const struct cne_acl_ctx *ctx)
{
    if (!ctx)
        return;
    cne_printf("acl context <%s>@%p\n", ctx->name, ctx);
    cne_printf("  alg=%" PRId32 "\n", ctx->alg);
    cne_printf("  max_rules=%" PRIu32 "\n", ctx->max_rules);
    cne_printf("  rule_size=%" PRIu32 "\n", ctx->rule_sz);
    cne_printf("  num_rules=%" PRIu32 "\n", ctx->num_rules);
    cne_printf("  num_categories=%" PRIu32 "\n", ctx->num_categories);
    cne_printf("  num_tries=%" PRIu32 "\n", ctx->num_tries);
}
