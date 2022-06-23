/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation.
 */
#include <cne_acl.h>              // for cne_acl_field, cne_acl_rule, cne_acl_field_t...
#include <cne_common.h>           // for CNE_PTR_ADD
#include <net/cne_ether.h>        // for cne_ether_hdr
#include <endian.h>               // for htobe16
#include <jcfg.h>                 // for jcfg_lport_t, jcfg_lport_by_index, jcfg_thd_t
#include <net/cne_ip.h>           // for cne_ipv4_hdr, CNE_IPV4
#include <stdbool.h>              // for bool
#include <stddef.h>               // for offsetof, NULL
#include <stdint.h>               // for uint32_t, uint8_t, uint16_t
#include <stdio.h>                // for printf
#include <stdlib.h>               // for free, malloc
#include <string.h>               // for memset
#include <txbuff.h>               // for txbuff_add, txbuff_t
#include <cne_log.h>              // for CNE_ERR_RET, CNE_LOG_ERR

#include "main.h"        // for fwd_port, MAX_BURST, acl_fwd_stats, get_dst_...

#define MAX_CATEGORIES     1
#define ACL_DENY_SIGNATURE 0xf0000000
#define MAX_ACL_RULE_NUM   100000
#define ACL_RULES_PER_PAGE 32

/*
 * Order in which fields are appearing in field definitions.
 */
enum { PROTO_FIELD_IPV4, SRC_FIELD_IPV4, DST_FIELD_IPV4, NUM_FIELDS_IPV4 };

/*
 * Order in which fields appear in data.
 */
enum { ACL_IPV4VLAN_PROTO, ACL_IPV4VLAN_SRC, ACL_IPV4VLAN_DST, ACL_IPV4VLAN_NUM };

/* ACL classify context */
struct acl_classify_t {
    const uint8_t *data_ptrs[BURST_SIZE];
    pktmbuf_t *pkts[BURST_SIZE];
    uint32_t acl_results[BURST_SIZE];
};

/* ACL context parameters */
static struct cne_acl_param acl_param = {.name         = "CNDPFWD-ACL",
                                         .rule_size    = CNE_ACL_RULE_SZ(NUM_FIELDS_IPV4),
                                         .max_rule_num = MAX_ACL_RULE_NUM};

#define ETH_HDR_LEN         (sizeof(struct cne_ether_hdr))
#define IPV4_PROTO_OFFSET   (offsetof(struct cne_ipv4_hdr, next_proto_id))
#define ACL_DATA_OFFSET     (ETH_HDR_LEN + IPV4_PROTO_OFFSET)
#define SRC_ADDR_OFFSET     (offsetof(struct cne_ipv4_hdr, src_addr))
#define DST_ADDR_OFFSET     (offsetof(struct cne_ipv4_hdr, dst_addr))
#define PROTO_ACL_OFFSET    0
#define SRC_ADDR_ACL_OFFSET (SRC_ADDR_OFFSET - IPV4_PROTO_OFFSET)
#define DST_ADDR_ACL_OFFSET (DST_ADDR_OFFSET - IPV4_PROTO_OFFSET)

// clang-format off
static struct cne_acl_config acl_config = {
    .num_categories = 1,
    .num_fields     = 3,
    .defs           = {
        {
            .type        = CNE_ACL_FIELD_TYPE_BITMASK,
            .size        = sizeof(uint8_t),
            .field_index = PROTO_FIELD_IPV4,
            .input_index = ACL_IPV4VLAN_PROTO,
            .offset      = PROTO_ACL_OFFSET,
        },
        {
            .type        = CNE_ACL_FIELD_TYPE_MASK,
            .size        = sizeof(uint32_t),
            .field_index = SRC_FIELD_IPV4,
            .input_index = ACL_IPV4VLAN_SRC,
            .offset      = SRC_ADDR_ACL_OFFSET,
        },
        {
            .type        = CNE_ACL_FIELD_TYPE_MASK,
            .size        = sizeof(uint32_t),
            .field_index = DST_FIELD_IPV4,
            .input_index = ACL_IPV4VLAN_DST,
            .offset      = DST_ADDR_ACL_OFFSET,
        },
    }
};
// clang-format on

static struct cne_acl_ctx *ctx;
static pthread_mutex_t ctx_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * This is the rule table, however due to the way the ACL works the base struct
 * does not include any actual rule data, so do *not* index the struct directly.
 * Instead, we provide a set of helper functions to perform operations on the
 * rule set. It works like a basic dynamic array.
 */
static struct acl_rule_table {
    uint8_t *rules; /**< Rule table */
    size_t len;     /**< Currnent number of rules in the table */
    size_t sz;      /**< Total number of available space in the table */
    size_t rule_sz; /**< Size of each individual rule. */
} acl_rules = {.rule_sz = CNE_ACL_RULE_SZ(NUM_FIELDS_IPV4)};

struct acl_rule_desc {
    uint32_t src_addr;
    uint8_t src_msk;
    uint32_t dst_addr;
    uint8_t dst_msk;
    bool deny;
};

#define ACL_NUM_PAGES(x) (((x) / ACL_RULES_PER_PAGE) + !!((x) % ACL_RULES_PER_PAGE))

static struct cne_acl_rule *
acl_tbl_get_rule(struct acl_rule_table *tbl, const size_t idx)
{
    return (struct cne_acl_rule *)CNE_PTR_ADD(tbl->rules, idx * tbl->rule_sz);
}

static int
acl_tbl_resize(struct acl_rule_table *tbl, const size_t new_sz)
{
    size_t newlen;
    uint8_t *newmem;

    /* do we need to do anything? */
    if (new_sz <= tbl->sz)
        return 0;
    newlen = tbl->rule_sz * new_sz;

    newmem = realloc(tbl->rules, newlen);
    if (newmem == NULL)
        return -ENOMEM;
    tbl->rules = newmem;
    tbl->sz    = newlen;
    return 0;
}

static void
acl_tbl_clear(struct acl_rule_table *tbl)
{
    /* just set length to 0, we'll overwrite stuff on addition anyway */
    tbl->len = 0;
}

static int
acl_tbl_ensure_capacity(struct acl_rule_table *tbl, const size_t sz)
{
    uint64_t new_sz;

    /* can we already fit in requested size? */
    if (sz <= tbl->sz)
        return 0;
    /* round-up to nearest power of 2 to avoid excessive reallocs */
    new_sz = cne_align64pow2(sz);
    /* limit it by max rule number in ACL context */
    new_sz = CNE_MIN(new_sz, acl_param.max_rule_num);
    /* can the new size at least fit in requested size? */
    if (new_sz < sz)
        return -ENOSPC;
    /* do we care about 32-bit targets? */

    return acl_tbl_resize(tbl, new_sz);
}

static void
acl_tbl_write_rule(struct acl_rule_table *tbl, const size_t idx, const struct acl_rule_desc *r)
{
    struct cne_acl_rule *rule = acl_tbl_get_rule(tbl, idx);

    /* we cannot start with 0 as 0 means no match */
    rule->data.userdata = idx + (r->deny ? ACL_DENY_SIGNATURE : 1);
    /* we don't use categories, so use all of them */
    rule->data.category_mask = -1;
    /* arbitrary value */
    rule->data.priority = CNE_ACL_MAX_PRIORITY - idx;
    /* ignore protocol type */
    rule->field[PROTO_FIELD_IPV4].value.u8      = 0;
    rule->field[PROTO_FIELD_IPV4].mask_range.u8 = 0;
    /* set source IP and mask */
    rule->field[SRC_FIELD_IPV4].value.u32     = r->src_addr;
    rule->field[SRC_FIELD_IPV4].mask_range.u8 = r->src_msk;
    /* set destination IP and mask */
    rule->field[DST_FIELD_IPV4].value.u32     = r->dst_addr;
    rule->field[DST_FIELD_IPV4].mask_range.u8 = r->dst_msk;
}

static void
acl_tbl_add_rule(struct acl_rule_table *tbl, const struct acl_rule_desc *rule)
{
    size_t newidx = tbl->len;

    acl_tbl_write_rule(tbl, newidx, rule);
    tbl->len++;
}

static int
acl_add_rule(const struct acl_rule_desc *rule)
{
    struct acl_rule_table *tbl = &acl_rules;
    size_t newidx              = tbl->len;
    int ret, mret;

    mret = pthread_mutex_lock(&ctx_mutex);
    if (mret != 0) {
        CNE_ERR("Mutex lock failed: %s\n", strerror(mret));
        return mret;
    }

    ret = acl_tbl_ensure_capacity(tbl, newidx);
    if (ret < 0)
        goto unlock;

    acl_tbl_add_rule(tbl, rule);

unlock:
    mret = pthread_mutex_unlock(&ctx_mutex);
    if (mret != 0)
        CNE_ERR("Mutex unlock failed: %s\n", strerror(mret));

    return ret;
}

static int
acl_clear(void)
{
    struct acl_rule_table *tbl = &acl_rules;
    int ret;

    ret = pthread_mutex_lock(&ctx_mutex);
    if (ret != 0) {
        CNE_ERR("Mutex lock failed: %s\n", strerror(ret));
        return ret;
    }

    acl_tbl_clear(tbl);

    ret = pthread_mutex_unlock(&ctx_mutex);
    if (ret != 0)
        CNE_ERR("Mutex unlock failed: %s\n", strerror(ret));

    return 0;
}

static inline int
validate_ipv4_pkt(const struct cne_ipv4_hdr *pkt, uint32_t link_len)
{
    /* From http://www.rfc-editor.org/rfc/rfc1812.txt section 5.2.2 */

    /*
     * 1. The packet length reported by the Link Layer must be large
     * enough to hold the minimum length legal IP datagram (20 bytes).
     */
    if (link_len < sizeof(struct cne_ipv4_hdr))
        return -1;

    /* 2. The IP checksum must be correct. */
    /* this is checked in H/W */

    /*
     * 3. The IP version number must be 4. If the version number is not 4
     * then the packet may be another version of IP, such as IPng or
     * ST-II.
     */
    if (((pkt->version_ihl) >> 4) != 4)
        return -1;
    /*
     * 4. The IP header length field must be large enough to hold the
     * minimum length legal IP datagram (20 bytes = 5 words).
     */
    if ((pkt->version_ihl & 0xf) < 5)
        return -1;

    /*
     * 5. The IP total length field must be large enough to hold the IP
     * datagram header, whose length is specified in the IP header length
     * field.
     */
    if (htobe16(pkt->total_length) < sizeof(struct cne_ipv4_hdr))
        return -1;

    return 0;
}

static uint16_t
populate_acl_classify(struct acl_classify_t *acl_classify_ctx, pktmbuf_t **pkts, unsigned int len)
{
    unsigned int i;
    uint16_t num = 0;

    for (i = 0; i < len; i++) {
        const struct cne_ipv4_hdr *ipv4_hdr;
        pktmbuf_t *m = pkts[i];

        ipv4_hdr = pktmbuf_mtod_offset(m, struct cne_ipv4_hdr *, ETH_HDR_LEN);

        /* Check to make sure the packet is valid (RFC1812) */
        if (validate_ipv4_pkt(ipv4_hdr, m->data_len) < 0) {
            /* not a valid IPv4 packet */
            pktmbuf_free(m);
            continue;
        }

        acl_classify_ctx->pkts[num]      = m;
        acl_classify_ctx->data_ptrs[num] = pktmbuf_mtod_offset(m, uint8_t *, ACL_DATA_OFFSET);
        num++;
    }
    return num;
}

int
acl_fwd_test(jcfg_lport_t *lport, struct fwd_info *fwd)
{
    /* do we forward non-matching packets? */
    const bool fwd_non_matching = fwd->test == ACL_PERMISSIVE_TEST;
    struct fwd_port *pd         = lport->priv_;
    struct acl_classify_t acl_classify_ctx;
    struct acl_fwd_stats *stats = &pd->acl_stats;
    uint16_t n_pkts, n_filtered, n_permit, n_deny;
    txbuff_t **txbuff;
    int i;

    if (!pd)
        return 0;

    txbuff = pd->thd->priv_;

    /* receive buffers from the network */
    switch (fwd->pkt_api) {
    case XSKDEV_PKT_API:
        n_pkts = xskdev_rx_burst(pd->xsk, (void **)pd->rx_mbufs, BURST_SIZE);
        break;
    case PKTDEV_PKT_API:
        n_pkts = pktdev_rx_burst(pd->lport, pd->rx_mbufs, BURST_SIZE);
        break;
    default:
        n_pkts = 0;
        break;
    }

    /* prepare ACL classification buffer */
    n_filtered = populate_acl_classify(&acl_classify_ctx, pd->rx_mbufs, n_pkts);

    stats->acl_prefilter_drop += n_pkts - n_filtered;

    /* if no packets found, exit early */
    if (n_filtered == 0)
        return 0;

    cne_acl_classify(ctx, acl_classify_ctx.data_ptrs, acl_classify_ctx.acl_results, n_filtered,
                     MAX_CATEGORIES);

    n_deny   = 0;
    n_permit = 0;

    for (i = 0; i < n_filtered; i++) {
        const uint32_t res = acl_classify_ctx.acl_results[i];
        pktmbuf_t *pkt     = acl_classify_ctx.pkts[i];
        /* are we dropping this packet? */
        const bool deny = (res & ACL_DENY_SIGNATURE) != 0;
        /* did we match anything? */
        const bool permit = (res != 0);
        /* do we forward this packet? */
        const bool forward = !deny && (fwd_non_matching | permit);

        if (forward) {
            uint8_t dst_lport = get_dst_lport(pktmbuf_mtod(pkt, void *));
            jcfg_lport_t *dst = jcfg_lport_by_index(fwd->jinfo, dst_lport);

            if (!dst)
                /* Cannot forward to non-existing port, so echo back on incoming interface */
                dst = lport;

            MAC_SWAP(pktmbuf_mtod(pkt, void *));
            (void)txbuff_add(txbuff[dst->lpid], pkt);
            n_permit++;
        } else {
            /* forward condition failed, drop the packet */
            pktmbuf_free(pkt);
            n_deny++;
        }
    }

    int nb_lports = jcfg_num_lports(fwd->jinfo);
    for (int i = 0; i < nb_lports; i++) {
        jcfg_lport_t *dst = jcfg_lport_by_index(fwd->jinfo, i);

        if (!dst)
            continue;

        /* Could hang here is we can never flush the TX packets */
        while (txbuff_count(txbuff[dst->lpid]) > 0)
            txbuff_flush(txbuff[dst->lpid]);
    }

    stats->acl_deny += n_deny;
    stats->acl_permit += n_permit;

    return 0;
}

static int
add_init_rules(struct cne_acl_ctx *ctx)
{
#define DST_DENY_RULE_NUM  100  /* Dst IP 100.x.x.0/24 */
#define SRC_DENY1_RULE_NUM 15   /* Src IP x.0.0.0/8 */
#define SRC_DENY2_RULE_NUM 15   /* Src IP 101.x.x.0/24 */
#define ALLOW_RULE_NUM     4096 /* IP 210.x.x.x/32 -> 110.x.x.x/32 */
    unsigned int i, total_num;
    int ret;

    total_num = DST_DENY_RULE_NUM + SRC_DENY1_RULE_NUM + SRC_DENY2_RULE_NUM + ALLOW_RULE_NUM;

    /* we know how many rules we will have in advance, so preallocate */
    ret = acl_tbl_ensure_capacity(&acl_rules, total_num);
    if (ret < 0)
        CNE_ERR_RET("Failed to allocate ACL rule table: %s\n", strerror(-ret));

    cne_printf("Creating destination IP deny rules:\n");
    cne_printf("   100.[0-99].0.0/24\n");

    for (i = 0; i < DST_DENY_RULE_NUM; i++) {
        struct acl_rule_desc rule = {0};

        rule.dst_addr = CNE_IPV4(100, i, 0, 0);
        rule.dst_msk  = 24;
        rule.deny     = true;

        acl_tbl_add_rule(&acl_rules, &rule);
    }

    cne_printf("Creating source IP deny rules...\n");
    cne_printf("   [10-34].0.0.0/8\n");

    for (i = 0; i < SRC_DENY1_RULE_NUM; i++) {
        struct acl_rule_desc rule = {0};

        rule.src_addr = CNE_IPV4(10 + i, 0, 0, 0);
        rule.src_msk  = 8;
        rule.deny     = true;

        acl_tbl_add_rule(&acl_rules, &rule);
    }

    cne_printf("Creating source IP deny rules...\n");
    cne_printf("   101.0.[0-14].0/24\n");

    for (i = 0; i < SRC_DENY2_RULE_NUM; i++) {
        struct acl_rule_desc rule = {0};

        rule.src_addr = CNE_IPV4(101, 0, i, 0);
        rule.src_msk  = 24;
        rule.deny     = true;

        acl_tbl_add_rule(&acl_rules, &rule);
    }

    cne_printf("Creating permit IP range remapping rules...\n");
    cne_printf("   210.0.[0-15].[0-255]/32 -> 110.0.[0-15].[0-255]/32\n");

    for (i = 0; i < ALLOW_RULE_NUM; i++) {
        const uint8_t octet1      = (uint8_t)(i & 0xFF);
        const uint8_t octet2      = (uint8_t)((i >> 8) & 0xFF);
        struct acl_rule_desc rule = {0};

        rule.src_addr = CNE_IPV4(210, 0, octet2, octet1);
        rule.src_msk  = 32;

        rule.dst_addr = CNE_IPV4(110, 0, octet2, octet1);
        rule.dst_msk  = 32;

        acl_tbl_add_rule(&acl_rules, &rule);
    }

    cne_printf("Adding rules to ACL context...\n");

    ret = cne_acl_add_rules(ctx, (const struct cne_acl_rule *)acl_rules.rules, total_num);
    if (ret < 0)
        CNE_ERR_RET("Failed to add rules: %s\n", strerror(-ret));

    return 0;
}

static int
thread_paused(jcfg_info_t *j __cne_unused, void *obj, void *arg __cne_unused, int idx __cne_unused)
{
    jcfg_thd_t *thd = obj;

    if (strcasecmp(thd->thread_type, "main") == 0)
        return 0;

    return thd->pause ? 0 : -1;
}

static bool
all_threads_stopped(struct fwd_info *fwd)
{
    /* zero return means all threads stopped */
    return jcfg_thread_foreach(fwd->jinfo, thread_paused, NULL) == 0;
}

int
fwd_acl_clear(uds_client_t *c __cne_unused, const char *cmd __cne_unused,
              const char *params __cne_unused)
{
    /* this just clears our rule table, it doesn't clear the ACL context itself */
    acl_clear();

    return 0;
}

static int
parse_acl_rule(char *buf, struct acl_rule_desc *rule)
{
    const char *src_ip_str, *src_mask_str, *dst_ip_str, *dst_mask_str, *rule_str;
    struct in_addr src_addr, dst_addr;
    long src_mask, dst_mask;
    char *state;
    bool deny;

    /* rules have a defined syntax: srcip/mask:dstip/mask:allow|deny */
    src_ip_str   = strtok_r(buf, "/", &state);
    src_mask_str = strtok_r(NULL, ":", &state);
    dst_ip_str   = strtok_r(NULL, "/", &state);
    dst_mask_str = strtok_r(NULL, ":", &state);
    rule_str     = strtok_r(NULL, ":", &state);

    if (src_ip_str == NULL || src_mask_str == NULL || dst_ip_str == NULL || dst_mask_str == NULL ||
        rule_str == NULL)
        return -1;

    /* try to parse IP address */
    if (inet_aton(src_ip_str, &src_addr) < 0)
        return -1;
    if (inet_aton(dst_ip_str, &dst_addr) < 0)
        return -1;

    /* try to parse mask - accept 0 to 32 */
    src_mask = strtol(src_mask_str, NULL, 10);
    if (src_mask < 0 || src_mask > 32)
        return -1;

    dst_mask = strtol(dst_mask_str, NULL, 10);
    if (dst_mask < 0 || dst_mask > 32)
        return -1;

    if (strcasecmp("allow", rule_str) == 0)
        deny = false;
    else if (strcasecmp("deny", rule_str) == 0)
        deny = true;
    else
        return -1;

    rule->deny     = deny;
    rule->src_addr = be32toh(src_addr.s_addr);
    rule->src_msk  = src_mask;
    rule->dst_addr = be32toh(dst_addr.s_addr);
    rule->dst_msk  = dst_mask;

    return 0;
}

int
fwd_acl_add_rule(uds_client_t *c, const char *cmd __cne_unused, const char *params)
{
    struct acl_rule_desc rule = {0};
    char *buf                 = NULL;
    int ret;

    if (params == NULL)
        goto bad_param;

    buf = strdup(params);
    if (buf == NULL) {
        uds_append(c, "\"error\":\"Failed to allocate memory\"");
        return 0;
    }

    ret = parse_acl_rule(buf, &rule);
    /* we don't need it any more */
    free(buf);

    if (ret < 0)
        goto bad_param;

    /* we've parsed the rule, now add it */
    ret = acl_add_rule(&rule);
    if (ret < 0) {
        uds_append(c, "\"error\":\"Failed to add ACL rule: %s\"", strerror(-ret));
        return 0;
    }

    return 0;

bad_param:
    uds_append(c, "\"error\":\"Command expects parameter: "
                  "<src IP>/<src mask>:<dst IP>/<dst mask>:<allow|deny>\"");

    return 0;
}

int
fwd_acl_build(uds_client_t *c, const char *cmd __cne_unused, const char *params __cne_unused)
{
    int ret, mret;
    struct fwd_info *fwd = (struct fwd_info *)(c->info->priv);

    /* we cannot do anything with ACL context unless all threads are stopped */
    if (!all_threads_stopped(fwd)) {
        uds_append(c, "\"error\":\"Not all forwarding threads are stopped\"");
        return 0;
    }

    mret = pthread_mutex_lock(&ctx_mutex);
    if (mret != 0) {
        CNE_ERR("Mutex lock failed: %s\n", strerror(mret));
        uds_append(c, "\"error\":\"Mutex lock failed\"");
        return 0;
    }

    /* if there's already an ACL context, free it */
    if (ctx != NULL) {
        cne_acl_free(ctx);
        ctx = NULL;
    }
    ctx = cne_acl_create(&acl_param);
    if (ctx == NULL) {
        uds_append(c, "\"error\":\"ACL context not initialized\"");
        goto unlock;
    }

    /* add all rules */
    ret = cne_acl_add_rules(ctx, (const struct cne_acl_rule *)acl_rules.rules, acl_rules.len);
    if (ret < 0) {
        uds_append(c, "\"error\":\"Cannot add ACL rules to context: %s\"", strerror(-ret));
        goto unlock;
    }

    /* build context */
    ret = cne_acl_build(ctx, &acl_config);
    if (ret != 0)
        uds_append(c, "\"error\":\"Cannot build ACL context: %s\"", strerror(-ret));

unlock:
    mret = pthread_mutex_unlock(&ctx_mutex);
    if (mret != 0)
        CNE_ERR("Mutex unlock failed: %s\n", strerror(mret));
    return 0;
}

static void
print_acl_info(uds_client_t *c)
{
    uds_append(c, "\"num rules\":%zu,", acl_rules.len);
    uds_append(c, "\"max rules\":%d,", acl_param.max_rule_num);
    uds_append(c, "\"rule pages\":%zu,", ACL_NUM_PAGES(acl_rules.len));
    uds_append(c, "\"rules per page\":%d", ACL_RULES_PER_PAGE);
}

static void
print_acl_rule(uds_client_t *c, size_t idx)
{
    struct cne_acl_rule *rule = acl_tbl_get_rule(&acl_rules, idx);
    struct in_addr src_addr, dst_addr;
    uint8_t src_msk, dst_msk;
    char *addr;
    bool deny;

    src_addr.s_addr = htobe32(rule->field[SRC_FIELD_IPV4].value.u32);
    src_msk         = rule->field[SRC_FIELD_IPV4].mask_range.u8;
    dst_addr.s_addr = htobe32(rule->field[DST_FIELD_IPV4].value.u32);
    dst_msk         = rule->field[DST_FIELD_IPV4].mask_range.u8;
    deny            = !!(rule->data.userdata & ACL_DENY_SIGNATURE);

    addr = inet_ntoa(src_addr);
    uds_append(c, "\"src addr\":\"%s/%d\",", addr, src_msk);
    addr = inet_ntoa(dst_addr);
    uds_append(c, "\"dst addr\":\"%s/%d\",", addr, dst_msk);
    uds_append(c, "\"type\":\"%s\"", deny ? "deny" : "allow");
}

static void
print_acl_rule_page(uds_client_t *c, size_t pg)
{
    size_t start, end, cur;
    if (pg >= ACL_NUM_PAGES(acl_rules.len)) {
        uds_append(c, "\"error\":\"Wrong page number\"");
        return;
    }
    start = pg * ACL_RULES_PER_PAGE;
    end   = CNE_MIN((pg + 1) * ACL_RULES_PER_PAGE, acl_rules.len);
    uds_append(c, "\"rules\":[");
    for (cur = start; cur < end; cur++) {
        if (cur != start)
            uds_append(c, ",");
        uds_append(c, "{");
        print_acl_rule(c, cur);
        uds_append(c, "}");
    }
    uds_append(c, "]");
}

struct acl_read_param {
    bool is_page; /**< Set to false to read a single ACL rule */
    size_t num;   /**< Which page/rule to read */
};
static int
parse_acl_read_param(const char *params, struct acl_read_param *out)
{
    const char *type, *num;
    char *state, *dup, *endp;
    int ret = -EINVAL;
    int64_t parsed;
    bool is_page;

    dup = strdup(params);
    if (dup == NULL)
        return -ENOMEM;

    type = strtok_r(dup, ":", &state);
    num  = strtok_r(NULL, ":", &state);
    if (type == NULL || num == NULL)
        goto end;

    if (strcasecmp(type, "p") == 0)
        is_page = true;
    else if (strcasecmp(type, "r") == 0)
        is_page = false;
    else
        goto end;

    parsed = strtoll(num, &endp, 10);
    /* there's some extra data at the end */
    if (*endp != '\0')
        goto end;
    if (parsed < 0)
        goto end;
    out->num     = (size_t)parsed;
    out->is_page = is_page;

    /* success */
    ret = 0;
end:
    free(dup);
    return ret;
}

int
fwd_acl_read(uds_client_t *c, const char *cmd __cne_unused, const char *params)
{
    struct acl_read_param prm;
    int ret, mret;

    /* don't allow for anything to happen with rules table */
    mret = pthread_mutex_lock(&ctx_mutex);
    if (mret != 0) {
        CNE_ERR("Mutex lock failed: %s\n", strerror(mret));
        uds_append(c, "\"error\":\"Mutex lock failed\"");
        return 0;
    }

    /* if no parameters, print out general info on rule table */
    if (params == NULL) {
        print_acl_info(c);
        goto unlock;
    }
    ret = parse_acl_read_param(params, &prm);
    if (ret < 0) {
        if (ret == -ENOMEM)
            uds_append(c, "\"error\":\"Cannot allocate memory\"");
        else if (ret == -EINVAL)
            uds_append(c, "\"error\":\"Parameter must be: 'p:<page num>' or 'r:<rule num>'\"");
        goto unlock;
    }

    if (prm.is_page) {
        print_acl_rule_page(c, prm.num);
    } else if (prm.num >= acl_rules.len) {
        uds_append(c, "\"error\":\"Wrong ACL rule number\"");
    } else {
        print_acl_rule(c, prm.num);
    }

unlock:
    mret = pthread_mutex_unlock(&ctx_mutex);
    if (mret != 0)
        CNE_ERR("Mutex unlock failed: %s\n", strerror(mret));
    return 0;
}

int
acl_init(struct fwd_info *fwd)
{
    int ret = -1, mret;

    cne_printf("Creating ACL context...\n");

    mret = pthread_mutex_lock(&ctx_mutex);
    if (mret != 0) {
        CNE_ERR("Mutex lock failed: %s\n", strerror(mret));
        return -1;
    }

    /* create ACL context */
    ctx = cne_acl_create(&acl_param);
    if (ctx == NULL)
        CNE_ERR_GOTO(unlock, "Could not create ACL context\n");

    /* add rules to context */
    if (add_init_rules(ctx) < 0)
        CNE_ERR_GOTO(unlock, "Could not add ACL rules\n");

    cne_printf("Building ACL runtime...\n");

    /* compile ACL matcher bytecode */
    if (cne_acl_build(ctx, &acl_config) < 0)
        CNE_ERR_GOTO(unlock, "Could not build ACL runtime\n");

    cne_printf("ACL rule table created successfully\n");

    if (fwd->test == ACL_STRICT_TEST) {
        cne_printf("ACL mode: strict\n");
        cne_printf("All traffic will be dropped unless matching a permit rule\n");
    } else {
        cne_printf("ACL mode: permissive\n");
        cne_printf("All traffic will be forwarded unless matching a deny rule\n");
    }
    /* success */
    ret = 0;

unlock:
    mret = pthread_mutex_unlock(&ctx_mutex);
    if (mret != 0)
        CNE_ERR("Mutex unlock failed: %s\n", strerror(mret));
    return ret;
}
