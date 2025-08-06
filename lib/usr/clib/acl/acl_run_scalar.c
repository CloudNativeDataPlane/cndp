/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2025 Intel Corporation
 */

#include <limits.h>        // for CHAR_BIT
#include <stdint.h>        // for uint32_t, int32_t, uint64_t, uint8_t, UINT8_MAX

#include "acl_run.h"           // for acl_match_check, parms, completion, MAX_SEAR...
#include "acl.h"               // for cne_acl_match_results, CNE_ACL_NODE_MATCH
#include "cne_acl.h"           // for CNE_ACL_RESULTS_MULTIPLIER
#include "cne_common.h"        // for cne_bsf32, CNE_DIM

/*
 * Resolve priority for multiple results (scalar version).
 * This consists comparing the priority of the current traversal with the
 * running set of results for the packet.
 * For each result, keep a running array of the result (rule number) and
 * its priority for each category.
 */
static inline void
resolve_priority_scalar(uint64_t transition, int n, const struct cne_acl_ctx *ctx,
                        struct parms *parms, const struct cne_acl_match_results *p,
                        uint32_t categories)
{
    uint32_t i;
    int32_t *saved_priority;
    uint32_t *saved_results;
    const int32_t *priority;
    const uint32_t *results;

    saved_results  = parms[n].cmplt->results;
    saved_priority = parms[n].cmplt->priority;

    /* results and priorities for completed trie */
    results  = p[transition].results;
    priority = p[transition].priority;

    /* if this is not the first completed trie */
    if (parms[n].cmplt->count != ctx->num_tries) {
        for (i = 0; i < categories; i += CNE_ACL_RESULTS_MULTIPLIER) {

            if (saved_priority[i] <= priority[i]) {
                saved_priority[i] = priority[i];
                saved_results[i]  = results[i];
            }
            if (saved_priority[i + 1] <= priority[i + 1]) {
                saved_priority[i + 1] = priority[i + 1];
                saved_results[i + 1]  = results[i + 1];
            }
            if (saved_priority[i + 2] <= priority[i + 2]) {
                saved_priority[i + 2] = priority[i + 2];
                saved_results[i + 2]  = results[i + 2];
            }
            if (saved_priority[i + 3] <= priority[i + 3]) {
                saved_priority[i + 3] = priority[i + 3];
                saved_results[i + 3]  = results[i + 3];
            }
        }
    } else {
        for (i = 0; i < categories; i += CNE_ACL_RESULTS_MULTIPLIER) {
            saved_priority[i]     = priority[i];
            saved_priority[i + 1] = priority[i + 1];
            saved_priority[i + 2] = priority[i + 2];
            saved_priority[i + 3] = priority[i + 3];

            saved_results[i]     = results[i];
            saved_results[i + 1] = results[i + 1];
            saved_results[i + 2] = results[i + 2];
            saved_results[i + 3] = results[i + 3];
        }
    }
}

static inline uint32_t
scan_forward(uint32_t input, uint32_t max)
{
    return (input == 0) ? max : cne_bsf32(input);
}

static inline uint64_t
scalar_transition(const uint64_t *trans_table, uint64_t transition, uint8_t input)
{
    uint32_t addr, index, ranges, x, a, b, c;

    /* break transition into component parts */
    ranges = transition >> (sizeof(index) * CHAR_BIT);
    index  = transition & ~CNE_ACL_NODE_INDEX;
    addr   = transition ^ index;

    if (index != CNE_ACL_NODE_DFA) {
        /* calc address for a QRANGE/SINGLE node */
        c = (uint32_t)input * SCALAR_QRANGE_MULT;
        a = ranges | SCALAR_QRANGE_MIN;
        a -= (c & SCALAR_QRANGE_MASK);
        b = c & SCALAR_QRANGE_MIN;
        a &= SCALAR_QRANGE_MIN;
        a ^= (ranges ^ b) & (a ^ b);
        x = scan_forward(a, 32) >> 3;
    } else {
        /* calc address for a DFA node */
        x = ranges >> (input / CNE_ACL_DFA_GR64_SIZE * CNE_ACL_DFA_GR64_BIT);
        x &= UINT8_MAX;
        x = input - x;
    }

    addr += x;

    /* pickup next transition */
    transition = *(trans_table + addr);
    return transition;
}

int
cne_acl_classify_scalar(const struct cne_acl_ctx *ctx, const uint8_t **data, uint32_t *results,
                        uint32_t num, uint32_t categories)
{
    int n;
    uint64_t transition0, transition1;
    uint32_t input0, input1;
    struct acl_flow_data flows;
    uint64_t index_array[MAX_SEARCHES_SCALAR];
    struct completion cmplt[MAX_SEARCHES_SCALAR] = {0};
    struct parms parms[MAX_SEARCHES_SCALAR]      = {0};

    acl_set_flow(&flows, cmplt, CNE_DIM(cmplt), data, results, num, categories, ctx->trans_table);

    for (n = 0; n < MAX_SEARCHES_SCALAR; n++) {
        cmplt[n].count = 0;
        index_array[n] = acl_start_next_trie(&flows, parms, n, ctx);
    }

    transition0 = index_array[0];
    transition1 = index_array[1];

    while ((transition0 | transition1) & CNE_ACL_NODE_MATCH) {
        transition0 = acl_match_check(transition0, 0, ctx, parms, &flows, resolve_priority_scalar);
        transition1 = acl_match_check(transition1, 1, ctx, parms, &flows, resolve_priority_scalar);
    }

    while (flows.started > 0) {

        input0 = GET_NEXT_4BYTES(parms, 0);
        input1 = GET_NEXT_4BYTES(parms, 1);

        for (n = 0; n < 4; n++) {

            transition0 = scalar_transition(flows.trans, transition0, (uint8_t)input0);
            input0 >>= CHAR_BIT;

            transition1 = scalar_transition(flows.trans, transition1, (uint8_t)input1);
            input1 >>= CHAR_BIT;
        }

        while ((transition0 | transition1) & CNE_ACL_NODE_MATCH) {
            transition0 =
                acl_match_check(transition0, 0, ctx, parms, &flows, resolve_priority_scalar);
            transition1 =
                acl_match_check(transition1, 1, ctx, parms, &flows, resolve_priority_scalar);
        }
    }
    return 0;
}
