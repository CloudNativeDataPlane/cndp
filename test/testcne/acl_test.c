/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2025 Intel Corporation
 */

#include <endian.h>            // for be16toh, htobe16, be32toh, htobe32
#include <tst_info.h>          // for tst_end, tst_start, tst_info_t
#include <getopt.h>            // for getopt_long, option
#include <net/cne_ip.h>        // for CNE_IPV4
#include <errno.h>             // for EINVAL
#include <inttypes.h>          // for PRIu32
#include <limits.h>            // for CHAR_BIT
#include <stddef.h>            // for offsetof
#include <stdint.h>            // for uint32_t, uint16_t, uint8_t, UINT16_MAX
#include <stdio.h>             // for printf, NULL, size_t, EOF
#include <string.h>            // for memcpy, memset

#include "acl_test.h"
#include "acl_test_data.h"        // for ipv4_7tuple, cne_acl_ipv4vlan_rule, CNE_A...
#include "cne_acl.h"              // for cne_acl_free, cne_acl_field_def, cne_acl_...
#include "cne_common.h"           // for CNE_DIM, CNE_MIN, CNE_MAX, CNE_SET_USED, SOCK...
#include "cne_log.h"              // for CNE_LOG, CNE_LOG_ERR

struct cne_acl_ctx;

#define BIT_SIZEOF(x) (sizeof(x) * CHAR_BIT)

#define LEN CNE_ACL_MAX_CATEGORIES

CNE_ACL_RULE_DEF(acl_ipv4vlan_rule, CNE_ACL_IPV4VLAN_NUM_FIELDS);

struct cne_acl_param acl_param = {
    .name         = "acl_ctx",
    .rule_size    = CNE_ACL_IPV4VLAN_RULE_SZ,
    .max_rule_num = 0x30000,
};

struct cne_acl_ipv4vlan_rule acl_rule = {
    .data          = {.priority = 1, .category_mask = 0xff},
    .src_port_low  = 0,
    .src_port_high = UINT16_MAX,
    .dst_port_low  = 0,
    .dst_port_high = UINT16_MAX,
};

const uint32_t ipv4_7tuple_layout[CNE_ACL_IPV4VLAN_NUM] = {
    offsetof(struct ipv4_7tuple, proto),    offsetof(struct ipv4_7tuple, vlan),
    offsetof(struct ipv4_7tuple, ip_src),   offsetof(struct ipv4_7tuple, ip_dst),
    offsetof(struct ipv4_7tuple, port_src),
};

/* byteswap to cpu or network order */
static void
bswap_test_data(struct ipv4_7tuple *data, int len, int to_be)
{
    int i;

    for (i = 0; i < len; i++) {

        if (to_be) {
            /* swap all bytes so that they are in network order */
            data[i].ip_dst   = htobe32(data[i].ip_dst);
            data[i].ip_src   = htobe32(data[i].ip_src);
            data[i].port_dst = htobe16(data[i].port_dst);
            data[i].port_src = htobe16(data[i].port_src);
            data[i].vlan     = htobe16(data[i].vlan);
            data[i].domain   = htobe16(data[i].domain);
        } else {
            data[i].ip_dst   = be32toh(data[i].ip_dst);
            data[i].ip_src   = be32toh(data[i].ip_src);
            data[i].port_dst = be16toh(data[i].port_dst);
            data[i].port_src = be16toh(data[i].port_src);
            data[i].vlan     = be16toh(data[i].vlan);
            data[i].domain   = be16toh(data[i].domain);
        }
    }
}

static int
acl_ipv4vlan_check_rule(const struct cne_acl_ipv4vlan_rule *rule)
{
    if (rule->src_port_low > rule->src_port_high || rule->dst_port_low > rule->dst_port_high ||
        rule->src_mask_len > BIT_SIZEOF(rule->src_addr) ||
        rule->dst_mask_len > BIT_SIZEOF(rule->dst_addr))
        return -EINVAL;
    return 0;
}

static void
acl_ipv4vlan_convert_rule(const struct cne_acl_ipv4vlan_rule *ri, struct acl_ipv4vlan_rule *ro)
{
    ro->data = ri->data;

    ro->field[CNE_ACL_IPV4VLAN_PROTO_FIELD].value.u8  = ri->proto;
    ro->field[CNE_ACL_IPV4VLAN_VLAN1_FIELD].value.u16 = ri->vlan;
    ro->field[CNE_ACL_IPV4VLAN_VLAN2_FIELD].value.u16 = ri->domain;
    ro->field[CNE_ACL_IPV4VLAN_SRC_FIELD].value.u32   = ri->src_addr;
    ro->field[CNE_ACL_IPV4VLAN_DST_FIELD].value.u32   = ri->dst_addr;
    ro->field[CNE_ACL_IPV4VLAN_SRCP_FIELD].value.u16  = ri->src_port_low;
    ro->field[CNE_ACL_IPV4VLAN_DSTP_FIELD].value.u16  = ri->dst_port_low;

    ro->field[CNE_ACL_IPV4VLAN_PROTO_FIELD].mask_range.u8  = ri->proto_mask;
    ro->field[CNE_ACL_IPV4VLAN_VLAN1_FIELD].mask_range.u16 = ri->vlan_mask;
    ro->field[CNE_ACL_IPV4VLAN_VLAN2_FIELD].mask_range.u16 = ri->domain_mask;
    ro->field[CNE_ACL_IPV4VLAN_SRC_FIELD].mask_range.u32   = ri->src_mask_len;
    ro->field[CNE_ACL_IPV4VLAN_DST_FIELD].mask_range.u32   = ri->dst_mask_len;
    ro->field[CNE_ACL_IPV4VLAN_SRCP_FIELD].mask_range.u16  = ri->src_port_high;
    ro->field[CNE_ACL_IPV4VLAN_DSTP_FIELD].mask_range.u16  = ri->dst_port_high;
}

/*
 * Add ipv4vlan rules to an existing ACL context.
 * This function is not multi-thread safe.
 *
 * @param ctx
 *   ACL context to add patterns to.
 * @param rules
 *   Array of rules to add to the ACL context.
 *   Note that all fields in cne_acl_ipv4vlan_rule structures are expected
 *   to be in host byte order.
 * @param num
 *   Number of elements in the input array of rules.
 * @return
 *   - -ENOMEM if there is no space in the ACL context for these rules.
 *   - -EINVAL if the parameters are invalid.
 *   - Zero if operation completed successfully.
 */
static int
cne_acl_ipv4vlan_add_rules(struct cne_acl_ctx *ctx, const struct cne_acl_ipv4vlan_rule *rules,
                           uint32_t num)
{
    int32_t rc;
    uint32_t i;
    struct acl_ipv4vlan_rule rv;

    if (ctx == NULL || rules == NULL)
        return -EINVAL;

    /* check input rules. */
    for (i = 0; i != num; i++) {
        rc = acl_ipv4vlan_check_rule(rules + i);
        if (rc != 0)
            CNE_ERR_RET_VAL(rc, "%s: rule #%u is invalid\n", __func__, i + 1);
    }

    /* perform conversion to the internal format and add to the context. */
    for (i = 0, rc = 0; i != num && rc == 0; i++) {
        acl_ipv4vlan_convert_rule(rules + i, &rv);
        rc = cne_acl_add_rules(ctx, (struct cne_acl_rule *)&rv, 1);
    }

    return rc;
}

static void
acl_ipv4vlan_config(struct cne_acl_config *cfg, const uint32_t layout[CNE_ACL_IPV4VLAN_NUM],
                    uint32_t num_categories)
{
    static const struct cne_acl_field_def ipv4_defs[CNE_ACL_IPV4VLAN_NUM_FIELDS] = {
        {
            .type        = CNE_ACL_FIELD_TYPE_BITMASK,
            .size        = sizeof(uint8_t),
            .field_index = CNE_ACL_IPV4VLAN_PROTO_FIELD,
            .input_index = CNE_ACL_IPV4VLAN_PROTO,
        },
        {
            .type        = CNE_ACL_FIELD_TYPE_BITMASK,
            .size        = sizeof(uint16_t),
            .field_index = CNE_ACL_IPV4VLAN_VLAN1_FIELD,
            .input_index = CNE_ACL_IPV4VLAN_VLAN,
        },
        {
            .type        = CNE_ACL_FIELD_TYPE_BITMASK,
            .size        = sizeof(uint16_t),
            .field_index = CNE_ACL_IPV4VLAN_VLAN2_FIELD,
            .input_index = CNE_ACL_IPV4VLAN_VLAN,
        },
        {
            .type        = CNE_ACL_FIELD_TYPE_MASK,
            .size        = sizeof(uint32_t),
            .field_index = CNE_ACL_IPV4VLAN_SRC_FIELD,
            .input_index = CNE_ACL_IPV4VLAN_SRC,
        },
        {
            .type        = CNE_ACL_FIELD_TYPE_MASK,
            .size        = sizeof(uint32_t),
            .field_index = CNE_ACL_IPV4VLAN_DST_FIELD,
            .input_index = CNE_ACL_IPV4VLAN_DST,
        },
        {
            .type        = CNE_ACL_FIELD_TYPE_RANGE,
            .size        = sizeof(uint16_t),
            .field_index = CNE_ACL_IPV4VLAN_SRCP_FIELD,
            .input_index = CNE_ACL_IPV4VLAN_PORTS,
        },
        {
            .type        = CNE_ACL_FIELD_TYPE_RANGE,
            .size        = sizeof(uint16_t),
            .field_index = CNE_ACL_IPV4VLAN_DSTP_FIELD,
            .input_index = CNE_ACL_IPV4VLAN_PORTS,
        },
    };

    memcpy(&cfg->defs, ipv4_defs, sizeof(ipv4_defs));
    cfg->num_fields = CNE_DIM(ipv4_defs);

    cfg->defs[CNE_ACL_IPV4VLAN_PROTO_FIELD].offset = layout[CNE_ACL_IPV4VLAN_PROTO];
    cfg->defs[CNE_ACL_IPV4VLAN_VLAN1_FIELD].offset = layout[CNE_ACL_IPV4VLAN_VLAN];
    cfg->defs[CNE_ACL_IPV4VLAN_VLAN2_FIELD].offset =
        layout[CNE_ACL_IPV4VLAN_VLAN] + cfg->defs[CNE_ACL_IPV4VLAN_VLAN1_FIELD].size;
    cfg->defs[CNE_ACL_IPV4VLAN_SRC_FIELD].offset  = layout[CNE_ACL_IPV4VLAN_SRC];
    cfg->defs[CNE_ACL_IPV4VLAN_DST_FIELD].offset  = layout[CNE_ACL_IPV4VLAN_DST];
    cfg->defs[CNE_ACL_IPV4VLAN_SRCP_FIELD].offset = layout[CNE_ACL_IPV4VLAN_PORTS];
    cfg->defs[CNE_ACL_IPV4VLAN_DSTP_FIELD].offset =
        layout[CNE_ACL_IPV4VLAN_PORTS] + cfg->defs[CNE_ACL_IPV4VLAN_SRCP_FIELD].size;

    cfg->num_categories = num_categories;
}

/*
 * Analyze set of ipv4vlan rules and build required internal
 * run-time structures.
 * This function is not multi-thread safe.
 *
 * @param ctx
 *   ACL context to build.
 * @param layout
 *   Layout of input data to search through.
 * @param num_categories
 *   Maximum number of categories to use in that build.
 * @return
 *   - -ENOMEM if couldn't allocate enough memory.
 *   - -EINVAL if the parameters are invalid.
 *   - Negative error code if operation failed.
 *   - Zero if operation completed successfully.
 */
static int
cne_acl_ipv4vlan_build(struct cne_acl_ctx *ctx, const uint32_t layout[CNE_ACL_IPV4VLAN_NUM],
                       uint32_t num_categories)
{
    struct cne_acl_config cfg;

    if (ctx == NULL || layout == NULL)
        return -EINVAL;

    memset(&cfg, 0, sizeof(cfg));
    acl_ipv4vlan_config(&cfg, layout, num_categories);
    return cne_acl_build(ctx, &cfg);
}

/*
 * Test scalar and SSE ACL lookup.
 */
static int
test_classify_run(struct cne_acl_ctx *acx, struct ipv4_7tuple test_data[], size_t dim)
{
    int ret, i;
    uint32_t result, count;
    uint32_t results[dim * CNE_ACL_MAX_CATEGORIES];
    const uint8_t *data[dim];
    /* swap all bytes in the data to network order */
    bswap_test_data(test_data, dim, 1);

    /* store pointers to test data */
    for (i = 0; i < (int)dim; i++)
        data[i] = (uint8_t *)&test_data[i];

    /**
     * these will run quite a few times, it's necessary to test code paths
     * from num=0 to num>8
     */
    for (count = 0; count <= dim; count++) {
        ret = cne_acl_classify(acx, data, results, count, CNE_ACL_MAX_CATEGORIES);
        if (ret != 0) {
            tst_error("Line %i: SSE classify failed!", __LINE__);
            goto err;
        }

        /* check if we allow everything we should allow */
        for (i = 0; i < (int)count; i++) {
            result = results[i * CNE_ACL_MAX_CATEGORIES + ACL_ALLOW];
            if (result != test_data[i].allow) {
                tst_error("Line %i: Error in allow results at %i "
                          "(expected %" PRIu32 " got %" PRIu32 ")!",
                          __LINE__, i, test_data[i].allow, result);
                ret = -EINVAL;
                goto err;
            }
        }

        /* check if we deny everything we should deny */
        for (i = 0; i < (int)count; i++) {
            result = results[i * CNE_ACL_MAX_CATEGORIES + ACL_DENY];
            if (result != test_data[i].deny) {
                tst_error("Line %i: Error in deny results at %i "
                          "(expected %" PRIu32 " got %" PRIu32 ")!",
                          __LINE__, i, test_data[i].deny, result);
                ret = -EINVAL;
                goto err;
            }
        }
    }

    /* make a quick check for scalar */
    ret = cne_acl_classify_alg(acx, data, results, dim, CNE_ACL_MAX_CATEGORIES,
                               CNE_ACL_CLASSIFY_SCALAR);
    if (ret != 0) {
        tst_error("Line %i: scalar classify failed!", __LINE__);
        goto err;
    }

    /* check if we allow everything we should allow */
    for (i = 0; i < (int)dim; i++) {
        result = results[i * CNE_ACL_MAX_CATEGORIES + ACL_ALLOW];
        if (result != test_data[i].allow) {
            tst_error("Line %i: Error in allow results at %i "
                      "(expected %" PRIu32 " got %" PRIu32 ")!",
                      __LINE__, i, test_data[i].allow, result);
            ret = -EINVAL;
            goto err;
        }
    }

    /* check if we deny everything we should deny */
    for (i = 0; i < (int)dim; i++) {
        result = results[i * CNE_ACL_MAX_CATEGORIES + ACL_DENY];
        if (result != test_data[i].deny) {
            tst_error("Line %i: Error in deny results at %i "
                      "(expected %" PRIu32 " got %" PRIu32 ")!",
                      __LINE__, i, test_data[i].deny, result);
            ret = -EINVAL;
            goto err;
        }
    }

    ret = 0;

err:
    /* swap data back to cpu order so that next time tests don't fail */
    bswap_test_data(test_data, dim, 0);
    if (ret != 0)
        tst_error("%s failed", __func__);
    return ret;
}

static int
test_classify_buid(struct cne_acl_ctx *acx, const struct cne_acl_ipv4vlan_rule *rules, uint32_t num)
{
    int ret;

    /* add rules to the context */
    ret = cne_acl_ipv4vlan_add_rules(acx, rules, num);
    if (ret != 0) {
        tst_error("Line %i: Adding rules to ACL context failed!", __LINE__);
        return ret;
    }

    /* try building the context */
    ret = cne_acl_ipv4vlan_build(acx, ipv4_7tuple_layout, CNE_ACL_MAX_CATEGORIES);
    if (ret != 0) {
        tst_error("Line %i: Building ACL context failed!", __LINE__);
        return ret;
    }

    return 0;
}

#define TEST_CLASSIFY_ITER 4

/*
 * Test scalar and SSE ACL lookup.
 */
static int
test_classify(void)
{
    struct cne_acl_ctx *acx;
    int i, ret;

    tst_info("%s(%s)", __func__, "Test scalar and SSE ACL lookup");

    acx = cne_acl_create(&acl_param);
    if (acx == NULL) {
        tst_error("Line %i: Error creating ACL context!", __LINE__);
        return -1;
    }

    ret = 0;
    for (i = 0; i != TEST_CLASSIFY_ITER; i++) {

        if ((i & 1) == 0)
            cne_acl_reset(acx);
        else
            cne_acl_reset_rules(acx);

        ret = test_classify_buid(acx, acl_test_rules, CNE_DIM(acl_test_rules));
        if (ret != 0) {
            tst_error("Line %i, iter: %d: "
                      "Adding rules to ACL context failed!",
                      __LINE__, i);
            break;
        }

        ret = test_classify_run(acx, acl_test_data, CNE_DIM(acl_test_data));
        if (ret != 0) {
            tst_error("Line %i, iter: %d: %s failed!", __LINE__, i, __func__);
            break;
        }

        /* reset rules and make sure that classify still works ok. */
        cne_acl_reset_rules(acx);
        ret = test_classify_run(acx, acl_test_data, CNE_DIM(acl_test_data));
        if (ret != 0) {
            tst_error("Line %i, iter: %d: %s failed!", __LINE__, i, __func__);
            break;
        }
    }

    cne_acl_free(acx);
    return ret;
}

/*
 * Test avx2 ACL lookup.
 */
static int
test_classify_avx2(void)
{
    struct cne_acl_ctx *acx;
    int i, ret;

    tst_info("%s(%s)", __func__, "Test avx2 ACL lookup");

    /* check if AVX2 is supported */
    if (!cne_cpu_get_flag_enabled(CNE_CPUFLAG_AVX2)) {
        tst_info("AVX2 not supported");
        return 0;
    }

    acx = cne_acl_create(&acl_param);
    if (acx == NULL) {
        tst_error("Line %i: Error creating ACL context!", __LINE__);
        return -1;
    }

    cne_acl_set_algo(acx, CNE_ACL_CLASSIFY_AVX2);

    ret = 0;
    for (i = 0; i != TEST_CLASSIFY_ITER; i++) {

        if ((i & 1) == 0)
            cne_acl_reset(acx);
        else
            cne_acl_reset_rules(acx);

        ret = test_classify_buid(acx, acl_test_rules, CNE_DIM(acl_test_rules));
        if (ret != 0) {
            tst_error("Line %i, iter: %d: "
                      "Adding rules to ACL context failed!",
                      __LINE__, i);
            break;
        }

        ret = test_classify_run(acx, acl_test_data, CNE_DIM(acl_test_data));
        if (ret != 0) {
            tst_error("Line %i, iter: %d: %s failed!", __LINE__, i, __func__);
            break;
        }

        /* reset rules and make sure that classify still works ok. */
        cne_acl_reset_rules(acx);
        ret = test_classify_run(acx, acl_test_data, CNE_DIM(acl_test_data));
        if (ret != 0) {
            tst_error("Line %i, iter: %d: %s failed!", __LINE__, i, __func__);
            break;
        }
    }

    cne_acl_free(acx);
    return ret;
}
/*
 * Test avx512x16 ACL lookup.
 */
static int
test_classify_avx512x16(void)
{
    struct cne_acl_ctx *acx;
    int i, ret;

    tst_info("%s(%s)", __func__, "Test avx512x16 ACL lookup");

    /* check if AVX512 is supported */
    if (!cne_cpu_get_flag_enabled(CNE_CPUFLAG_AVX512F)) {
        tst_info("AVX512 not supported");
        return 0;
    }

    acx = cne_acl_create(&acl_param);
    if (acx == NULL) {
        tst_error("Line %i: Error creating ACL context!", __LINE__);
        return -1;
    }

    cne_acl_set_algo(acx, CNE_ACL_CLASSIFY_AVX512X16);

    ret = 0;
    for (i = 0; i != TEST_CLASSIFY_ITER; i++) {

        if ((i & 1) == 0)
            cne_acl_reset(acx);
        else
            cne_acl_reset_rules(acx);

        ret = test_classify_buid(acx, acl_test_rules, CNE_DIM(acl_test_rules));
        if (ret != 0) {
            tst_error("Line %i, iter: %d: "
                      "Adding rules to ACL context failed!",
                      __LINE__, i);
            break;
        }

        ret = test_classify_run(acx, acl_test_data, CNE_DIM(acl_test_data));
        if (ret != 0) {
            tst_error("Line %i, iter: %d: %s failed!", __LINE__, i, __func__);
            break;
        }

        /* reset rules and make sure that classify still works ok. */
        cne_acl_reset_rules(acx);
        ret = test_classify_run(acx, acl_test_data, CNE_DIM(acl_test_data));
        if (ret != 0) {
            tst_error("Line %i, iter: %d: %s failed!", __LINE__, i, __func__);
            break;
        }
    }

    cne_acl_free(acx);
    return ret;
}
/*
 * Test avx512x16 ACL lookup.
 */
static int
test_classify_avx512x32(void)
{
    struct cne_acl_ctx *acx;
    int i, ret;

    tst_info("%s(%s)", __func__, "Test avx512x16 ACL lookup");

    /* check if AVX512 is supported */
    if (!cne_cpu_get_flag_enabled(CNE_CPUFLAG_AVX512F)) {
        tst_info("AVX512 not supported");
        return 0;
    }

    acx = cne_acl_create(&acl_param);
    if (acx == NULL) {
        tst_error("Line %i: Error creating ACL context!", __LINE__);
        return -1;
    }

    cne_acl_set_algo(acx, CNE_ACL_CLASSIFY_AVX512X32);

    ret = 0;
    for (i = 0; i != TEST_CLASSIFY_ITER; i++) {

        if ((i & 1) == 0)
            cne_acl_reset(acx);
        else
            cne_acl_reset_rules(acx);

        ret = test_classify_buid(acx, acl_test_rules, CNE_DIM(acl_test_rules));
        if (ret != 0) {
            tst_error("Line %i, iter: %d: "
                      "Adding rules to ACL context failed!",
                      __LINE__, i);
            break;
        }

        ret = test_classify_run(acx, acl_test_data, CNE_DIM(acl_test_data));
        if (ret != 0) {
            tst_error("Line %i, iter: %d: %s failed!", __LINE__, i, __func__);
            break;
        }

        /* reset rules and make sure that classify still works ok. */
        cne_acl_reset_rules(acx);
        ret = test_classify_run(acx, acl_test_data, CNE_DIM(acl_test_data));
        if (ret != 0) {
            tst_error("Line %i, iter: %d: %s failed!", __LINE__, i, __func__);
            break;
        }
    }

    cne_acl_free(acx);
    return ret;
}

static int
test_build_ports_range(void)
{
    static const struct cne_acl_ipv4vlan_rule test_rules[] = {
        {
            /* match all packets. */
            .data =
                {
                    .userdata      = 1,
                    .category_mask = ACL_ALLOW_MASK,
                    .priority      = 101,
                },
            .src_port_low  = 0,
            .src_port_high = UINT16_MAX,
            .dst_port_low  = 0,
            .dst_port_high = UINT16_MAX,
        },
        {
            /* match all packets with dst ports [54-65280]. */
            .data =
                {
                    .userdata      = 2,
                    .category_mask = ACL_ALLOW_MASK,
                    .priority      = 102,
                },
            .src_port_low  = 0,
            .src_port_high = UINT16_MAX,
            .dst_port_low  = 54,
            .dst_port_high = 65280,
        },
        {
            /* match all packets with dst ports [0-52]. */
            .data =
                {
                    .userdata      = 3,
                    .category_mask = ACL_ALLOW_MASK,
                    .priority      = 103,
                },
            .src_port_low  = 0,
            .src_port_high = UINT16_MAX,
            .dst_port_low  = 0,
            .dst_port_high = 52,
        },
        {
            /* match all packets with dst ports [53]. */
            .data =
                {
                    .userdata      = 4,
                    .category_mask = ACL_ALLOW_MASK,
                    .priority      = 99,
                },
            .src_port_low  = 0,
            .src_port_high = UINT16_MAX,
            .dst_port_low  = 53,
            .dst_port_high = 53,
        },
        {
            /* match all packets with dst ports [65279-65535]. */
            .data =
                {
                    .userdata      = 5,
                    .category_mask = ACL_ALLOW_MASK,
                    .priority      = 98,
                },
            .src_port_low  = 0,
            .src_port_high = UINT16_MAX,
            .dst_port_low  = 65279,
            .dst_port_high = UINT16_MAX,
        },
    };

    static struct ipv4_7tuple test_data[] = {
        {
            .proto    = 6,
            .ip_src   = CNE_IPV4(10, 1, 1, 1),
            .ip_dst   = CNE_IPV4(192, 168, 0, 33),
            .port_dst = 53,
            .allow    = 1,
        },
        {
            .proto    = 6,
            .ip_src   = CNE_IPV4(127, 84, 33, 1),
            .ip_dst   = CNE_IPV4(1, 2, 3, 4),
            .port_dst = 65281,
            .allow    = 1,
        },
    };

    struct cne_acl_ctx *acx;
    int32_t ret, i, j;
    uint32_t results[CNE_DIM(test_data)];
    const uint8_t *data[CNE_DIM(test_data)];

    tst_info("%s(%s)", __func__, "Test ports ACLs");

    acx = cne_acl_create(&acl_param);
    if (acx == NULL) {
        tst_error("Line %i: Error creating ACL context!", __LINE__);
        return -1;
    }

    /* swap all bytes in the data to network order */
    bswap_test_data(test_data, CNE_DIM(test_data), 1);

    /* store pointers to test data */
    for (i = 0; i != CNE_DIM(test_data); i++)
        data[i] = (uint8_t *)&test_data[i];

    for (i = 0; i != CNE_DIM(test_rules); i++) {
        cne_acl_reset(acx);
        ret = test_classify_buid(acx, test_rules, i + 1);
        if (ret != 0) {
            tst_error("Line %i, iter: %d: "
                      "Adding rules to ACL context failed!",
                      __LINE__, i);
            break;
        }
        ret = cne_acl_classify(acx, data, results, CNE_DIM(data), 1);
        if (ret != 0) {
            tst_error("Line %i, iter: %d: classify failed!", __LINE__, i);
            break;
        }

        /* check results */
        for (j = 0; j != CNE_DIM(results); j++) {
            if (results[j] != test_data[j].allow) {
                tst_error("Line %i: Error in allow results at %i "
                          "(expected %" PRIu32 " got %" PRIu32 ")!",
                          __LINE__, j, test_data[j].allow, results[j]);
                ret = -EINVAL;
            }
        }
    }

    bswap_test_data(test_data, CNE_DIM(test_data), 0);

    cne_acl_free(acx);
    return ret;
}

static void
convert_rule(const struct cne_acl_ipv4vlan_rule *ri, struct acl_ipv4vlan_rule *ro)
{
    ro->data = ri->data;

    ro->field[CNE_ACL_IPV4VLAN_PROTO_FIELD].value.u8  = ri->proto;
    ro->field[CNE_ACL_IPV4VLAN_VLAN1_FIELD].value.u16 = ri->vlan;
    ro->field[CNE_ACL_IPV4VLAN_VLAN2_FIELD].value.u16 = ri->domain;
    ro->field[CNE_ACL_IPV4VLAN_SRC_FIELD].value.u32   = ri->src_addr;
    ro->field[CNE_ACL_IPV4VLAN_DST_FIELD].value.u32   = ri->dst_addr;
    ro->field[CNE_ACL_IPV4VLAN_SRCP_FIELD].value.u16  = ri->src_port_low;
    ro->field[CNE_ACL_IPV4VLAN_DSTP_FIELD].value.u16  = ri->dst_port_low;

    ro->field[CNE_ACL_IPV4VLAN_PROTO_FIELD].mask_range.u8  = ri->proto_mask;
    ro->field[CNE_ACL_IPV4VLAN_VLAN1_FIELD].mask_range.u16 = ri->vlan_mask;
    ro->field[CNE_ACL_IPV4VLAN_VLAN2_FIELD].mask_range.u16 = ri->domain_mask;
    ro->field[CNE_ACL_IPV4VLAN_SRC_FIELD].mask_range.u32   = ri->src_mask_len;
    ro->field[CNE_ACL_IPV4VLAN_DST_FIELD].mask_range.u32   = ri->dst_mask_len;
    ro->field[CNE_ACL_IPV4VLAN_SRCP_FIELD].mask_range.u16  = ri->src_port_high;
    ro->field[CNE_ACL_IPV4VLAN_DSTP_FIELD].mask_range.u16  = ri->dst_port_high;
}

/*
 * Convert IPV4 source and destination from CNE_ACL_FIELD_TYPE_MASK to
 * CNE_ACL_FIELD_TYPE_BITMASK.
 */
static void
convert_rule_1(const struct cne_acl_ipv4vlan_rule *ri, struct acl_ipv4vlan_rule *ro)
{
    uint32_t v;

    convert_rule(ri, ro);
    v = ro->field[CNE_ACL_IPV4VLAN_SRC_FIELD].mask_range.u32;
    ro->field[CNE_ACL_IPV4VLAN_SRC_FIELD].mask_range.u32 = CNE_ACL_MASKLEN_TO_BITMASK(v, sizeof(v));
    v = ro->field[CNE_ACL_IPV4VLAN_DST_FIELD].mask_range.u32;
    ro->field[CNE_ACL_IPV4VLAN_DST_FIELD].mask_range.u32 = CNE_ACL_MASKLEN_TO_BITMASK(v, sizeof(v));
}

/*
 * Convert IPV4 source and destination from CNE_ACL_FIELD_TYPE_MASK to
 * CNE_ACL_FIELD_TYPE_RANGE.
 */
static void
convert_rule_2(const struct cne_acl_ipv4vlan_rule *ri, struct acl_ipv4vlan_rule *ro)
{
    uint32_t hi, lo, mask;

    convert_rule(ri, ro);

    mask = ro->field[CNE_ACL_IPV4VLAN_SRC_FIELD].mask_range.u32;
    mask = CNE_ACL_MASKLEN_TO_BITMASK(mask, sizeof(mask));
    lo   = ro->field[CNE_ACL_IPV4VLAN_SRC_FIELD].value.u32 & mask;
    hi   = lo + ~mask;
    ro->field[CNE_ACL_IPV4VLAN_SRC_FIELD].value.u32      = lo;
    ro->field[CNE_ACL_IPV4VLAN_SRC_FIELD].mask_range.u32 = hi;

    mask = ro->field[CNE_ACL_IPV4VLAN_DST_FIELD].mask_range.u32;
    mask = CNE_ACL_MASKLEN_TO_BITMASK(mask, sizeof(mask));
    lo   = ro->field[CNE_ACL_IPV4VLAN_DST_FIELD].value.u32 & mask;
    hi   = lo + ~mask;
    ro->field[CNE_ACL_IPV4VLAN_DST_FIELD].value.u32      = lo;
    ro->field[CNE_ACL_IPV4VLAN_DST_FIELD].mask_range.u32 = hi;
}

/*
 * Convert cne_acl_ipv4vlan_rule: swap VLAN and PORTS rule fields.
 */
static void
convert_rule_3(const struct cne_acl_ipv4vlan_rule *ri, struct acl_ipv4vlan_rule *ro)
{
    struct cne_acl_field t1, t2;

    convert_rule(ri, ro);

    t1 = ro->field[CNE_ACL_IPV4VLAN_VLAN1_FIELD];
    t2 = ro->field[CNE_ACL_IPV4VLAN_VLAN2_FIELD];

    ro->field[CNE_ACL_IPV4VLAN_VLAN1_FIELD] = ro->field[CNE_ACL_IPV4VLAN_SRCP_FIELD];
    ro->field[CNE_ACL_IPV4VLAN_VLAN2_FIELD] = ro->field[CNE_ACL_IPV4VLAN_DSTP_FIELD];

    ro->field[CNE_ACL_IPV4VLAN_SRCP_FIELD] = t1;
    ro->field[CNE_ACL_IPV4VLAN_DSTP_FIELD] = t2;
}

/*
 * Convert cne_acl_ipv4vlan_rule: swap SRC and DST IPv4 address rules.
 */
static void
convert_rule_4(const struct cne_acl_ipv4vlan_rule *ri, struct acl_ipv4vlan_rule *ro)
{
    struct cne_acl_field t;

    convert_rule(ri, ro);

    t                                     = ro->field[CNE_ACL_IPV4VLAN_SRC_FIELD];
    ro->field[CNE_ACL_IPV4VLAN_SRC_FIELD] = ro->field[CNE_ACL_IPV4VLAN_DST_FIELD];

    ro->field[CNE_ACL_IPV4VLAN_DST_FIELD] = t;
}

static void
ipv4vlan_config(struct cne_acl_config *cfg, const uint32_t layout[CNE_ACL_IPV4VLAN_NUM],
                uint32_t num_categories)
{
    static const struct cne_acl_field_def ipv4_defs[CNE_ACL_IPV4VLAN_NUM_FIELDS] = {
        {
            .type        = CNE_ACL_FIELD_TYPE_BITMASK,
            .size        = sizeof(uint8_t),
            .field_index = CNE_ACL_IPV4VLAN_PROTO_FIELD,
            .input_index = CNE_ACL_IPV4VLAN_PROTO,
        },
        {
            .type        = CNE_ACL_FIELD_TYPE_BITMASK,
            .size        = sizeof(uint16_t),
            .field_index = CNE_ACL_IPV4VLAN_VLAN1_FIELD,
            .input_index = CNE_ACL_IPV4VLAN_VLAN,
        },
        {
            .type        = CNE_ACL_FIELD_TYPE_BITMASK,
            .size        = sizeof(uint16_t),
            .field_index = CNE_ACL_IPV4VLAN_VLAN2_FIELD,
            .input_index = CNE_ACL_IPV4VLAN_VLAN,
        },
        {
            .type        = CNE_ACL_FIELD_TYPE_MASK,
            .size        = sizeof(uint32_t),
            .field_index = CNE_ACL_IPV4VLAN_SRC_FIELD,
            .input_index = CNE_ACL_IPV4VLAN_SRC,
        },
        {
            .type        = CNE_ACL_FIELD_TYPE_MASK,
            .size        = sizeof(uint32_t),
            .field_index = CNE_ACL_IPV4VLAN_DST_FIELD,
            .input_index = CNE_ACL_IPV4VLAN_DST,
        },
        {
            .type        = CNE_ACL_FIELD_TYPE_RANGE,
            .size        = sizeof(uint16_t),
            .field_index = CNE_ACL_IPV4VLAN_SRCP_FIELD,
            .input_index = CNE_ACL_IPV4VLAN_PORTS,
        },
        {
            .type        = CNE_ACL_FIELD_TYPE_RANGE,
            .size        = sizeof(uint16_t),
            .field_index = CNE_ACL_IPV4VLAN_DSTP_FIELD,
            .input_index = CNE_ACL_IPV4VLAN_PORTS,
        },
    };

    memcpy(&cfg->defs, ipv4_defs, sizeof(ipv4_defs));
    cfg->num_fields = CNE_DIM(ipv4_defs);

    cfg->defs[CNE_ACL_IPV4VLAN_PROTO_FIELD].offset = layout[CNE_ACL_IPV4VLAN_PROTO];
    cfg->defs[CNE_ACL_IPV4VLAN_VLAN1_FIELD].offset = layout[CNE_ACL_IPV4VLAN_VLAN];
    cfg->defs[CNE_ACL_IPV4VLAN_VLAN2_FIELD].offset =
        layout[CNE_ACL_IPV4VLAN_VLAN] + cfg->defs[CNE_ACL_IPV4VLAN_VLAN1_FIELD].size;
    cfg->defs[CNE_ACL_IPV4VLAN_SRC_FIELD].offset  = layout[CNE_ACL_IPV4VLAN_SRC];
    cfg->defs[CNE_ACL_IPV4VLAN_DST_FIELD].offset  = layout[CNE_ACL_IPV4VLAN_DST];
    cfg->defs[CNE_ACL_IPV4VLAN_SRCP_FIELD].offset = layout[CNE_ACL_IPV4VLAN_PORTS];
    cfg->defs[CNE_ACL_IPV4VLAN_DSTP_FIELD].offset =
        layout[CNE_ACL_IPV4VLAN_PORTS] + cfg->defs[CNE_ACL_IPV4VLAN_SRCP_FIELD].size;

    cfg->num_categories = num_categories;
}

static int
convert_rules(struct cne_acl_ctx *acx,
              void (*convert)(const struct cne_acl_ipv4vlan_rule *, struct acl_ipv4vlan_rule *),
              const struct cne_acl_ipv4vlan_rule *rules, uint32_t num)
{
    int32_t rc;
    uint32_t i;
    struct acl_ipv4vlan_rule r;

    for (i = 0; i != num; i++) {
        convert(rules + i, &r);
        rc = cne_acl_add_rules(acx, (struct cne_acl_rule *)&r, 1);
        if (rc != 0) {
            tst_error("Line %i: Adding rule %u to ACL context "
                      "failed with error code: %d",
                      __LINE__, i, rc);
            return rc;
        }
    }

    return 0;
}

static void
convert_config(struct cne_acl_config *cfg)
{
    ipv4vlan_config(cfg, ipv4_7tuple_layout, CNE_ACL_MAX_CATEGORIES);
}

/*
 * Convert cne_acl_ipv4vlan_rule to use CNE_ACL_FIELD_TYPE_BITMASK.
 */
static void
convert_config_1(struct cne_acl_config *cfg)
{
    ipv4vlan_config(cfg, ipv4_7tuple_layout, CNE_ACL_MAX_CATEGORIES);
    cfg->defs[CNE_ACL_IPV4VLAN_SRC_FIELD].type = CNE_ACL_FIELD_TYPE_BITMASK;
    cfg->defs[CNE_ACL_IPV4VLAN_DST_FIELD].type = CNE_ACL_FIELD_TYPE_BITMASK;
}

/*
 * Convert cne_acl_ipv4vlan_rule to use CNE_ACL_FIELD_TYPE_RANGE.
 */
static void
convert_config_2(struct cne_acl_config *cfg)
{
    ipv4vlan_config(cfg, ipv4_7tuple_layout, CNE_ACL_MAX_CATEGORIES);
    cfg->defs[CNE_ACL_IPV4VLAN_SRC_FIELD].type = CNE_ACL_FIELD_TYPE_RANGE;
    cfg->defs[CNE_ACL_IPV4VLAN_DST_FIELD].type = CNE_ACL_FIELD_TYPE_RANGE;
}

/*
 * Convert cne_acl_ipv4vlan_rule: swap VLAN and PORTS rule definitions.
 */
static void
convert_config_3(struct cne_acl_config *cfg)
{
    struct cne_acl_field_def t1, t2;

    ipv4vlan_config(cfg, ipv4_7tuple_layout, CNE_ACL_MAX_CATEGORIES);

    t1 = cfg->defs[CNE_ACL_IPV4VLAN_VLAN1_FIELD];
    t2 = cfg->defs[CNE_ACL_IPV4VLAN_VLAN2_FIELD];

    /* swap VLAN1 and SRCP rule definition. */
    cfg->defs[CNE_ACL_IPV4VLAN_VLAN1_FIELD]             = cfg->defs[CNE_ACL_IPV4VLAN_SRCP_FIELD];
    cfg->defs[CNE_ACL_IPV4VLAN_VLAN1_FIELD].field_index = t1.field_index;
    cfg->defs[CNE_ACL_IPV4VLAN_VLAN1_FIELD].input_index = t1.input_index;

    /* swap VLAN2 and DSTP rule definition. */
    cfg->defs[CNE_ACL_IPV4VLAN_VLAN2_FIELD]             = cfg->defs[CNE_ACL_IPV4VLAN_DSTP_FIELD];
    cfg->defs[CNE_ACL_IPV4VLAN_VLAN2_FIELD].field_index = t2.field_index;
    cfg->defs[CNE_ACL_IPV4VLAN_VLAN2_FIELD].input_index = t2.input_index;

    cfg->defs[CNE_ACL_IPV4VLAN_SRCP_FIELD].type   = t1.type;
    cfg->defs[CNE_ACL_IPV4VLAN_SRCP_FIELD].size   = t1.size;
    cfg->defs[CNE_ACL_IPV4VLAN_SRCP_FIELD].offset = t1.offset;

    cfg->defs[CNE_ACL_IPV4VLAN_DSTP_FIELD].type   = t2.type;
    cfg->defs[CNE_ACL_IPV4VLAN_DSTP_FIELD].size   = t2.size;
    cfg->defs[CNE_ACL_IPV4VLAN_DSTP_FIELD].offset = t2.offset;
}

/*
 * Convert cne_acl_ipv4vlan_rule: swap SRC and DST ip address rule definitions.
 */
static void
convert_config_4(struct cne_acl_config *cfg)
{
    struct cne_acl_field_def t;

    ipv4vlan_config(cfg, ipv4_7tuple_layout, CNE_ACL_MAX_CATEGORIES);

    t = cfg->defs[CNE_ACL_IPV4VLAN_SRC_FIELD];

    cfg->defs[CNE_ACL_IPV4VLAN_SRC_FIELD]             = cfg->defs[CNE_ACL_IPV4VLAN_DST_FIELD];
    cfg->defs[CNE_ACL_IPV4VLAN_SRC_FIELD].field_index = t.field_index;
    cfg->defs[CNE_ACL_IPV4VLAN_SRC_FIELD].input_index = t.input_index;

    cfg->defs[CNE_ACL_IPV4VLAN_DST_FIELD].type   = t.type;
    cfg->defs[CNE_ACL_IPV4VLAN_DST_FIELD].size   = t.size;
    cfg->defs[CNE_ACL_IPV4VLAN_DST_FIELD].offset = t.offset;
}

static int
build_convert_rules(struct cne_acl_ctx *acx, void (*config)(struct cne_acl_config *),
                    size_t max_size)
{
    struct cne_acl_config cfg;

    memset(&cfg, 0, sizeof(cfg));
    config(&cfg);
    cfg.max_size = max_size;
    return cne_acl_build(acx, &cfg);
}

static int
test_convert_rules(const char *desc, void (*config)(struct cne_acl_config *),
                   void (*convert)(const struct cne_acl_ipv4vlan_rule *,
                                   struct acl_ipv4vlan_rule *))
{
    struct cne_acl_ctx *acx;
    int32_t rc;
    uint32_t i;
    static const size_t mem_sizes[] = {0, -1};

    tst_info("%s(%s)", __func__, desc);

    acx = cne_acl_create(&acl_param);
    if (acx == NULL) {
        tst_error("Line %i: Error creating ACL context!", __LINE__);
        return -1;
    }

    rc = convert_rules(acx, convert, acl_test_rules, CNE_DIM(acl_test_rules));
    if (rc != 0)
        tst_error("Line %i: Error converting ACL rules!", __LINE__);

    for (i = 0; rc == 0 && i != CNE_DIM(mem_sizes); i++) {

        rc = build_convert_rules(acx, config, mem_sizes[i]);
        if (rc != 0) {
            tst_error("Line %i: Error @ build_convert_rules(%zu)!", __LINE__, mem_sizes[i]);
            break;
        }

        rc = test_classify_run(acx, acl_test_data, CNE_DIM(acl_test_data));
        if (rc != 0)
            tst_error("%s failed at line %i, max_size=%zu", __func__, __LINE__, mem_sizes[i]);
    }

    cne_acl_free(acx);
    return rc;
}

static int
test_convert(void)
{
    static const struct {
        const char *desc;
        void (*config)(struct cne_acl_config *);
        void (*convert)(const struct cne_acl_ipv4vlan_rule *, struct acl_ipv4vlan_rule *);
    } convert_param[] = {
        {
            "acl_ipv4vlan_tuple",
            convert_config,
            convert_rule,
        },
        {
            "acl_ipv4vlan_tuple, CNE_ACL_FIELD_TYPE_BITMASK type "
            "for IPv4",
            convert_config_1,
            convert_rule_1,
        },
        {
            "acl_ipv4vlan_tuple, CNE_ACL_FIELD_TYPE_RANGE type "
            "for IPv4",
            convert_config_2,
            convert_rule_2,
        },
        {
            "acl_ipv4vlan_tuple: swap VLAN and PORTs order",
            convert_config_3,
            convert_rule_3,
        },
        {
            "acl_ipv4vlan_tuple: swap SRC and DST IPv4 order",
            convert_config_4,
            convert_rule_4,
        },
    };

    uint32_t i;
    int32_t rc;

    tst_info("%s(%s)", __func__, "Test convert rules");

    for (i = 0; i != CNE_DIM(convert_param); i++) {
        rc = test_convert_rules(convert_param[i].desc, convert_param[i].config,
                                convert_param[i].convert);
        if (rc != 0) {
            tst_error("%s for test-case: %s failed, error code: %d;", __func__,
                      convert_param[i].desc, rc);
            return rc;
        }
    }

    return 0;
}

/*
 * Test wrong layout behavior
 * This test supplies the ACL context with invalid layout, which results in
 * ACL matching the wrong stuff. However, it should match the wrong stuff
 * the right way. We switch around source and destination addresses,
 * source and destination ports, and protocol will point to first byte of
 * destination port.
 */
static int
test_invalid_layout(void)
{
    struct cne_acl_ctx *acx;
    int ret, i;

    uint32_t results[CNE_DIM(invalid_layout_data)];
    const uint8_t *data[CNE_DIM(invalid_layout_data)];

    const uint32_t layout[CNE_ACL_IPV4VLAN_NUM] = {
        /* proto points to destination port's first byte */
        offsetof(struct ipv4_7tuple, port_dst),

        0, /* VLAN not used */

        /* src and dst addresses are swapped */
        offsetof(struct ipv4_7tuple, ip_dst),
        offsetof(struct ipv4_7tuple, ip_src),

        /*
         * we can't swap ports here, so we will swap
         * them in the data
         */
        offsetof(struct ipv4_7tuple, port_src),
    };

    tst_info("%s(%s)", __func__, "Test wrong layout behavior");

    acx = cne_acl_create(&acl_param);
    if (acx == NULL) {
        tst_error("Line %i: Error creating ACL context!", __LINE__);
        return -1;
    }

    /* putting a lot of rules into the context results in greater
     * coverage numbers. it doesn't matter if they are identical */
    for (i = 0; i < 1000; i++) {
        /* add rules to the context */
        ret = cne_acl_ipv4vlan_add_rules(acx, invalid_layout_rules, CNE_DIM(invalid_layout_rules));
        if (ret != 0) {
            tst_error("Line %i: Adding rules to ACL context failed!", __LINE__);
            cne_acl_free(acx);
            return -1;
        }
    }

    /* try building the context */
    ret = cne_acl_ipv4vlan_build(acx, layout, 1);
    if (ret != 0) {
        tst_error("Line %i: Building ACL context failed!", __LINE__);
        cne_acl_free(acx);
        return -1;
    }

    /* swap all bytes in the data to network order */
    bswap_test_data(invalid_layout_data, CNE_DIM(invalid_layout_data), 1);

    /* prepare data */
    for (i = 0; i < (int)CNE_DIM(invalid_layout_data); i++) {
        data[i] = (uint8_t *)&invalid_layout_data[i];
    }

    /* classify tuples */
    ret = cne_acl_classify_alg(acx, data, results, CNE_DIM(results), 1, CNE_ACL_CLASSIFY_SCALAR);
    if (ret != 0) {
        tst_error("Line %i: SSE classify failed!", __LINE__);
        cne_acl_free(acx);
        return -1;
    }

    for (i = 0; i < (int)CNE_DIM(results); i++) {
        if (results[i] != invalid_layout_data[i].allow) {
            tst_error("Line %i: Wrong results at %i "
                      "(result=%u, should be %u)!",
                      __LINE__, i, results[i], invalid_layout_data[i].allow);
            goto err;
        }
    }

    /* classify tuples (scalar) */
    ret = cne_acl_classify_alg(acx, data, results, CNE_DIM(results), 1, CNE_ACL_CLASSIFY_SCALAR);

    if (ret != 0) {
        tst_error("Line %i: Scalar classify failed!", __LINE__);
        cne_acl_free(acx);
        return -1;
    }

    for (i = 0; i < (int)CNE_DIM(results); i++) {
        if (results[i] != invalid_layout_data[i].allow) {
            tst_error("Line %i: Wrong results at %i "
                      "(result=%u, should be %u)!",
                      __LINE__, i, results[i], invalid_layout_data[i].allow);
            goto err;
        }
    }

    cne_acl_free(acx);

    /* swap data back to cpu order so that next time tests don't fail */
    bswap_test_data(invalid_layout_data, CNE_DIM(invalid_layout_data), 0);

    return 0;
err:

    /* swap data back to cpu order so that next time tests don't fail */
    bswap_test_data(invalid_layout_data, CNE_DIM(invalid_layout_data), 0);

    cne_acl_free(acx);

    tst_error("%s failed", __func__);
    return -1;
}

/*
 * Test creating and finding ACL contexts, and adding rules
 */
static int
test_create_find_add(void)
{
    struct cne_acl_param param;
    struct cne_acl_ctx *acx, *acx2;
    struct cne_acl_ipv4vlan_rule rules[LEN];

    const uint32_t layout[CNE_ACL_IPV4VLAN_NUM] = {0};

    const char *acx_name  = "acx";
    const char *acx2_name = "acx2";
    int i, ret;

    tst_info("%s(%s)", __func__, "Test creating and finding ACL contexts");

    /* create two contexts */
    memcpy(&param, &acl_param, sizeof(param));
    param.max_rule_num = 2;

    param.name = acx_name;
    acx        = cne_acl_create(&param);
    if (acx == NULL) {
        tst_error("Line %i: Error creating %s!", __LINE__, acx_name);
        return -1;
    }

    param.name = acx2_name;
    acx2       = cne_acl_create(&param);
    if (acx2 == NULL || acx2 == acx) {
        tst_error("Line %i: Error creating %s!", __LINE__, acx2_name);
        cne_acl_free(acx);
        return -1;
    }

    /* free context */
    cne_acl_free(acx);

    /* create valid (but severely limited) acx */
    memcpy(&param, &acl_param, sizeof(param));
    param.max_rule_num = LEN;

    acx = cne_acl_create(&param);
    if (acx == NULL) {
        tst_error("Line %i: Error creating %s!", __LINE__, param.name);
        goto err;
    }

    /* create dummy acl */
    for (i = 0; i < LEN; i++) {
        memcpy(&rules[i], &acl_rule, sizeof(struct cne_acl_ipv4vlan_rule));
        /* skip zero */
        rules[i].data.userdata = i + 1;
        /* one rule per category */
        rules[i].data.category_mask = 1 << i;
    }

    /* try filling up the context */
    ret = cne_acl_ipv4vlan_add_rules(acx, rules, LEN);
    if (ret != 0) {
        tst_error("Line %i: Adding %i rules to ACL context failed!", __LINE__, LEN);
        goto err;
    }

    /* try adding to a (supposedly) full context */
    ret = cne_acl_ipv4vlan_add_rules(acx, rules, 1);
    if (ret == 0) {
        tst_error("Line %i: Adding rules to full ACL context should"
                  "have failed!",
                  __LINE__);
        goto err;
    }

    /* try building the context */
    ret = cne_acl_ipv4vlan_build(acx, layout, CNE_ACL_MAX_CATEGORIES);
    if (ret != 0) {
        tst_error("Line %i: Building ACL context failed!", __LINE__);
        goto err;
    }

    cne_acl_free(acx);
    cne_acl_free(acx2);

    return 0;
err:
    cne_acl_free(acx);
    cne_acl_free(acx2);
    tst_error("%s failed", __func__);
    return -1;
}

/*
 * test various invalid rules
 */
static int
test_invalid_rules(void)
{
    struct cne_acl_ctx *acx;
    int ret;

    struct cne_acl_ipv4vlan_rule rule;

    tst_info("%s(%s)", __func__, "test various invalid rules");

    acx = cne_acl_create(&acl_param);
    if (acx == NULL) {
        tst_error("Line %i: Error creating ACL context!", __LINE__);
        return -1;
    }

    /* test invecned high/low source and destination ports.
     * originally, there was a problem with memory consumption when using
     * such rules.
     */
    /* create dummy acl */
    memcpy(&rule, &acl_rule, sizeof(struct cne_acl_ipv4vlan_rule));
    rule.data.userdata = 1;
    rule.dst_port_low  = 0xfff0;
    rule.dst_port_high = 0x0010;

    /* add rules to context and try to build it */
    ret = cne_acl_ipv4vlan_add_rules(acx, &rule, 1);
    if (ret == 0) {
        tst_error("Line %i: Adding rules to ACL context "
                  "should have failed!",
                  __LINE__);
        goto err;
    }

    rule.dst_port_low  = 0x0;
    rule.dst_port_high = 0xffff;
    rule.src_port_low  = 0xfff0;
    rule.src_port_high = 0x0010;

    /* add rules to context and try to build it */
    ret = cne_acl_ipv4vlan_add_rules(acx, &rule, 1);
    if (ret == 0) {
        tst_error("Line %i: Adding rules to ACL context "
                  "should have failed!",
                  __LINE__);
        goto err;
    }

    rule.dst_port_low  = 0x0;
    rule.dst_port_high = 0xffff;
    rule.src_port_low  = 0x0;
    rule.src_port_high = 0xffff;

    rule.dst_mask_len = 33;

    /* add rules to context and try to build it */
    ret = cne_acl_ipv4vlan_add_rules(acx, &rule, 1);
    if (ret == 0) {
        tst_error("Line %i: Adding rules to ACL context "
                  "should have failed!",
                  __LINE__);
        goto err;
    }

    rule.dst_mask_len = 0;
    rule.src_mask_len = 33;

    /* add rules to context and try to build it */
    ret = cne_acl_ipv4vlan_add_rules(acx, &rule, 1);
    if (ret == 0) {
        tst_error("Line %i: Adding rules to ACL context "
                  "should have failed!",
                  __LINE__);
        goto err;
    }

    cne_acl_free(acx);

    return 0;

err:
    cne_acl_free(acx);
    tst_error("%s failed", __func__);
    return -1;
}

/*
 * test functions by passing invalid or
 * non-workable parameters.
 *
 * we do very limited testing of classify functions here
 * because those are performance-critical and
 * thus don't do much parameter checking.
 */
static int
test_invalid_parameters(void)
{
    struct cne_acl_param param;
    struct cne_acl_ctx *acx;
    struct cne_acl_ipv4vlan_rule rule;
    int result;

    uint32_t layout[CNE_ACL_IPV4VLAN_NUM] = {0};

    tst_info("%s(%s)", __func__, "test functions by passing invalid params");

    /**
     * cne_ac_create()
     */

    /* NULL param */
    acx = cne_acl_create(NULL);
    if (acx != NULL) {
        tst_error("Line %i: ACL context creation with NULL param "
                  "should have failed!",
                  __LINE__);
        cne_acl_free(acx);
        return -1;
    }

    /* zero rule size */
    memcpy(&param, &acl_param, sizeof(param));
    param.rule_size = 0;

    acx = cne_acl_create(&param);
    if (acx == NULL) {
        tst_error("Line %i: ACL context creation with zero rule len "
                  "failed!",
                  __LINE__);
        return -1;
    } else
        cne_acl_free(acx);

    /* zero max rule num */
    memcpy(&param, &acl_param, sizeof(param));
    param.max_rule_num = 0;

    acx = cne_acl_create(&param);
    if (acx == NULL) {
        tst_error("Line %i: ACL context creation with zero rule num "
                  "failed!",
                  __LINE__);
        return -1;
    } else
        cne_acl_free(acx);

    /* NULL name */
    memcpy(&param, &acl_param, sizeof(param));
    param.name = NULL;

    acx = cne_acl_create(&param);
    if (acx != NULL) {
        tst_error("Line %i: ACL context creation with NULL name "
                  "should have failed!",
                  __LINE__);
        cne_acl_free(acx);
        return -1;
    }

    /**
     * cne_acl_ipv4vlan_add_rules
     */

    /* initialize everything */
    memcpy(&param, &acl_param, sizeof(param));
    acx = cne_acl_create(&param);
    if (acx == NULL) {
        tst_error("Line %i: ACL context creation failed!", __LINE__);
        return -1;
    }

    memcpy(&rule, &acl_rule, sizeof(rule));

    /* NULL context */
    result = cne_acl_ipv4vlan_add_rules(NULL, &rule, 1);
    if (result == 0) {
        tst_error("Line %i: Adding rules with NULL ACL context "
                  "should have failed!",
                  __LINE__);
        cne_acl_free(acx);
        return -1;
    }

    /* NULL rule */
    result = cne_acl_ipv4vlan_add_rules(acx, NULL, 1);
    if (result == 0) {
        tst_error("Line %i: Adding NULL rule to ACL context "
                  "should have failed!",
                  __LINE__);
        cne_acl_free(acx);
        return -1;
    }

    /* zero count (should succeed) */
    result = cne_acl_ipv4vlan_add_rules(acx, &rule, 0);
    if (result != 0) {
        tst_error("Line %i: Adding 0 rules to ACL context failed!", __LINE__);
        cne_acl_free(acx);
        return -1;
    }

    /* free ACL context */
    cne_acl_free(acx);

    /**
     * cne_acl_ipv4vlan_build
     */

    /* reinitialize context */
    memcpy(&param, &acl_param, sizeof(param));
    acx = cne_acl_create(&param);
    if (acx == NULL) {
        tst_error("Line %i: ACL context creation failed!", __LINE__);
        return -1;
    }

    /* NULL context */
    result = cne_acl_ipv4vlan_build(NULL, layout, 1);
    if (result == 0) {
        tst_error("Line %i: Building with NULL context "
                  "should have failed!",
                  __LINE__);
        cne_acl_free(acx);
        return -1;
    }

    /* NULL layout */
    result = cne_acl_ipv4vlan_build(acx, NULL, 1);
    if (result == 0) {
        tst_error("Line %i: Building with NULL layout "
                  "should have failed!",
                  __LINE__);
        cne_acl_free(acx);
        return -1;
    }

    /* zero categories (should not fail) */
    result = cne_acl_ipv4vlan_build(acx, layout, 0);
    if (result == 0) {
        tst_error("Line %i: Building with 0 categories should fail!", __LINE__);
        cne_acl_free(acx);
        return -1;
    }

    /* SSE classify test */

    /* cover zero categories in classify (should not fail) */
    result = cne_acl_classify(acx, NULL, NULL, 0, 0);
    if (result != 0) {
        tst_error("Line %i: SSE classify with zero categories "
                  "failed!",
                  __LINE__);
        cne_acl_free(acx);
        return -1;
    }

    /* cover invalid but positive categories in classify */
    result = cne_acl_classify(acx, NULL, NULL, 0, 3);
    if (result == 0) {
        tst_error("Line %i: SSE classify with 3 categories "
                  "should have failed!",
                  __LINE__);
        cne_acl_free(acx);
        return -1;
    }

    /* scalar classify test */

    /* cover zero categories in classify (should not fail) */
    result = cne_acl_classify_alg(acx, NULL, NULL, 0, 0, CNE_ACL_CLASSIFY_SCALAR);
    if (result != 0) {
        tst_error("Line %i: Scalar classify with zero categories "
                  "failed!",
                  __LINE__);
        cne_acl_free(acx);
        return -1;
    }

    /* cover invalid but positive categories in classify */
    result = cne_acl_classify(acx, NULL, NULL, 0, 3);
    if (result == 0) {
        tst_error("Line %i: Scalar classify with 3 categories "
                  "should have failed!",
                  __LINE__);
        cne_acl_free(acx);
        return -1;
    }

    /* free ACL context */
    cne_acl_free(acx);

    /**
     * make sure void functions don't crash with NULL parameters
     */

    cne_acl_free(NULL);

    cne_acl_dump(NULL);

    return 0;
}

/**
 * Various tests that don't test much but improve coverage
 */
static int
test_misc(void)
{
    struct cne_acl_param param;
    struct cne_acl_ctx *acx;

    tst_info("%s(%s)", __func__, "Various tests to improve coverage.");

    /* create context */
    memcpy(&param, &acl_param, sizeof(param));

    acx = cne_acl_create(&param);
    if (acx == NULL) {
        tst_error("Line %i: Error creating ACL context!", __LINE__);
        return -1;
    }

    cne_acl_dump(acx);

    cne_acl_free(acx);

    return 0;
}

static uint32_t
get_u32_range_max(void)
{
    uint32_t i, max;

    max = 0;
    for (i = 0; i != CNE_DIM(acl_u32_range_test_rules); i++)
        max = CNE_MAX(max, acl_u32_range_test_rules[i].src_mask_len);
    return max;
}

static uint32_t
get_u32_range_min(void)
{
    uint32_t i, min;

    min = UINT32_MAX;
    for (i = 0; i != CNE_DIM(acl_u32_range_test_rules); i++)
        min = CNE_MIN(min, acl_u32_range_test_rules[i].src_addr);
    return min;
}

static const struct cne_acl_ipv4vlan_rule *
find_u32_range_rule(uint32_t val)
{
    uint32_t i;

    for (i = 0; i != CNE_DIM(acl_u32_range_test_rules); i++) {
        if (val >= acl_u32_range_test_rules[i].src_addr &&
            val <= acl_u32_range_test_rules[i].src_mask_len)
            return acl_u32_range_test_rules + i;
    }
    return NULL;
}

static void
fill_u32_range_data(struct ipv4_7tuple tdata[], uint32_t start, uint32_t num)
{
    uint32_t i;
    const struct cne_acl_ipv4vlan_rule *r;

    for (i = 0; i != num; i++) {
        tdata[i].ip_src = start + i;
        r               = find_u32_range_rule(start + i);
        if (r != NULL)
            tdata[i].allow = r->data.userdata;
    }
}

static int
test_u32_range(void)
{
    int32_t rc;
    uint32_t i, k, max, min;
    struct cne_acl_ctx *acx;
    struct acl_ipv4vlan_rule r;
    struct ipv4_7tuple test_data[64];

    acx = cne_acl_create(&acl_param);
    if (acx == NULL) {
        tst_error("%s#%i: Error creating ACL context!", __func__, __LINE__);
        return -1;
    }

    for (i = 0; i != CNE_DIM(acl_u32_range_test_rules); i++) {
        convert_rule(&acl_u32_range_test_rules[i], &r);
        rc = cne_acl_add_rules(acx, (struct cne_acl_rule *)&r, 1);
        if (rc != 0) {
            tst_error("%s#%i: Adding rule to ACL context "
                      "failed with error code: %d",
                      __func__, __LINE__, rc);
            cne_acl_free(acx);
            return rc;
        }
    }

    rc = build_convert_rules(acx, convert_config_2, 0);
    if (rc != 0) {
        tst_error("%s#%i Error @ build_convert_rules!", __func__, __LINE__);
        cne_acl_free(acx);
        return rc;
    }

    max = get_u32_range_max();
    min = get_u32_range_min();

    max = CNE_MAX(max, max + 1);
    min = CNE_MIN(min, min - 1);

    tst_info("%s(starting range test from %u to %u)", __func__, __LINE__, min, max);

    for (i = min; i <= max; i += k) {

        k = CNE_MIN(max - i + 1, (uint32_t)CNE_DIM(test_data));

        memset(test_data, 0, sizeof(test_data));
        fill_u32_range_data(test_data, i, k);

        rc = test_classify_run(acx, test_data, k);
        if (rc != 0) {
            tst_error("%s#%d failed at [%u, %u) interval", __func__, __LINE__, i, i + k);
            break;
        }
    }

    cne_acl_free(acx);
    return rc;
}

int
acl_main(int argc, char **argv)
{
    tst_info_t *tst;
    int verbose = 0, opt;
    char **argvopt;
    int option_index;
    static const struct option lgopts[] = {{NULL, 0, 0, 0}};

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "V", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'V':
            verbose = 1;
            break;
        default:
            break;
        }
    }
    CNE_SET_USED(verbose);

    tst = tst_start("ACL");

    if (test_invalid_parameters() < 0)
        goto err;
    if (test_invalid_rules() < 0)
        goto err;
    if (test_create_find_add() < 0)
        goto err;
    if (test_invalid_layout() < 0)
        goto err;
    if (test_misc() < 0)
        goto err;
    if (test_classify() < 0)
        goto err;
    if (test_classify_avx2() < 0)
        goto err;
    if (test_classify_avx512x16() < 0)
        goto err;
    if (test_classify_avx512x32() < 0)
        goto err;
    if (test_build_ports_range() < 0)
        goto err;
    if (test_convert() < 0)
        goto err;
    if (test_u32_range() < 0)
        goto err;

    tst_ok("All ACL tests passed");
    tst_end(tst, TST_PASSED);
    return 0;
err:
    tst_error("Current test failed causing early return");
    tst_end(tst, TST_FAILED);
    return -1;
}
