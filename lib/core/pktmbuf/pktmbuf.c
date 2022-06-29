/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 * Copyright (c) 2019-2020 6WIND S.A.
 */

#include <string.h>                       // for memcpy, memset, strcpy
#include <stdio.h>                        // for fprintf, NULL, snprintf, fflush
#include <stdint.h>                       // for uint32_t, uint16_t, UINT16_MAX
#include <inttypes.h>                     // for PRIu32, PRIx64
#include <cne_common.h>                   // for CNE_DEFAULT_SET, CNE_MAX_SET, CNE...
#include <cne_log.h>                      // for CNE_LOG_ERR, CNE_ERR_RET, CNE_ERR...
#include <cne_branch_prediction.h>        // for unlikely
#include <pktmbuf.h>
#include <stdlib.h>        // for calloc, free
#include <pthread.h>

#include <cne_mutex_helper.h>

static TAILQ_HEAD(pktmbuf_info_list, pktmbuf_info_s) pinfo_list;
static pthread_mutex_t pinfo_list_mutex;

static inline void
pi_list_lock(void)
{
    int ret = pthread_mutex_lock(&pinfo_list_mutex);

    if (ret)
        CNE_WARN("failed: %s\n", strerror(ret));
}

static inline void
pi_list_unlock(void)
{
    int ret = pthread_mutex_unlock(&pinfo_list_mutex);

    if (ret)
        CNE_WARN("failed: %s\n", strerror(ret));
}

/**
 * The packet mbuf constructor.
 *
 * This function initializes some fields in the mbuf structure that are
 * not modified by the user once created (origin pool, buffer start
 * address, and so on).
 *
 * @param pi
 *   The pool data pointer from which mbufs originate.
 * @param m
 *   The mbuf to initialize.
 * @param sz
 *   Size of the buffer.
 * @param idx
 *   The index of the buffer in the mempool.
 * @param ud
 *   The user defined pointer value
 * @return
 *   0 on success or -1 on error
 */
static int
__mbuf_init(pktmbuf_info_t *pi, pktmbuf_t *m, uint32_t sz, uint32_t idx, void *ud __cne_unused)
{
    if (!m || !pi)
        CNE_ERR_RET("pktmbuf_info_t pointer or mbuf pointer invalid\n");
    if (sz == 0)
        CNE_ERR_RET("buffer size is zero\n");

    memset(m, 0, sz);

    /* start of buffer is after pktmbuf structure */
    m->buf_addr = (char *)m + sizeof(pktmbuf_t);
    m->buf_len  = (uint16_t)sz - sizeof(pktmbuf_t);

    /* keep some headroom between start of buffer and data */
    m->data_off = CNE_MIN(CNE_PKTMBUF_HEADROOM, (uint16_t)m->buf_len);

    /* init some constant fields */
    m->pooldata   = pi;
    m->lport      = CNE_MBUF_INVALID_PORT;
    m->meta_index = idx;
    pktmbuf_refcnt_set(m, 1);

    return 0;
}

int
pktmbuf_iterate(pktmbuf_info_t *pi, pktmbuf_cb_t cb, void *ud)
{
    if (!pi)
        CNE_ERR_RET("pktmbuf_info_t pointer is NULL");

    if (cb) {
        char *addr = pi->addr; /* the function will return NULL if mm is NULL */

        if (!addr)
            CNE_ERR_RET("buffer address is NULL");

        /* Allow the caller to iterate over the buffers */
        for (uint32_t i = 0; i < pi->bufcnt; i++) {
            if (cb(pi, (pktmbuf_t *)addr, pi->bufsz, i, ud))
                CNE_ERR_RET("user buffer callback has failed\n");

            addr += pi->bufsz;
        }
    }

    return 0;
}

int
pktmbuf_pool_cfg(pktmbuf_pool_cfg_t *c, void *addr, uint32_t bufcnt, uint32_t bufsz,
                 uint32_t cache_sz, void *metadata, uint32_t metadata_bufsz, mbuf_ops_t *ops)
{
    if (!c || !addr)
        CNE_ERR_RET("config pointer or address is invalid\n");

    CNE_MAX_SET(cache_sz, MEMPOOL_CACHE_MAX_SIZE);

    /* Use default values when a field is zero */
    CNE_DEFAULT_SET(cache_sz, 0, MEMPOOL_CACHE_MAX_SIZE);
    CNE_DEFAULT_SET(bufcnt, 0, DEFAULT_MBUF_COUNT);
    CNE_DEFAULT_SET(bufsz, 0, DEFAULT_MBUF_SIZE);

    /* Make sure the mbuf size is cache aligned */
    if (CNE_CACHE_LINE_ROUNDUP(bufsz) != bufsz)
        CNE_ERR_RET("bufsz is not cache aligned\n");

    if ((!metadata && metadata_bufsz) || (metadata && !metadata_bufsz))
        CNE_ERR_RET("metadata and/or metadata_bufsz are invalid\n");

    /* Size of metadata buffer should be a multiple of a cacheline */
    if (metadata && (CNE_CACHE_LINE_ROUNDUP(metadata_bufsz) != metadata_bufsz))
        CNE_ERR_RET("metadata bufsz is not a multiple of a cacheline\n");

    c->addr           = addr;
    c->bufcnt         = bufcnt;
    c->bufsz          = bufsz;
    c->cache_sz       = cache_sz;
    c->ops            = ops;
    c->metadata       = metadata;
    c->metadata_bufsz = metadata_bufsz;

    return 0;
}

pktmbuf_info_t *
pktmbuf_pool_cfg_create(const pktmbuf_pool_cfg_t *cfg)
{
    pktmbuf_pool_cfg_t _cfg, *c = &_cfg;
    pktmbuf_info_t *pi = NULL;

    if (!cfg)
        goto leave;

    if (pktmbuf_pool_cfg(c, cfg->addr, cfg->bufcnt, cfg->bufsz, cfg->cache_sz, cfg->metadata,
                         cfg->metadata_bufsz, cfg->ops) < 0)
        goto leave;

    pi = calloc(1, sizeof(pktmbuf_info_t));
    if (!pi)
        CNE_ERR_GOTO(leave, "unable to allocate pktmbuf_info_t structure\n");

    pi->addr           = c->addr;
    pi->bufcnt         = c->bufcnt;
    pi->bufsz          = c->bufsz;
    pi->cache_sz       = c->cache_sz;
    pi->metadata       = c->metadata;
    pi->metadata_bufsz = c->metadata_bufsz;

    pktmbuf_set_default_ops(&pi->ops);

    if (c->ops)
        memcpy(&pi->ops, c->ops, sizeof(mbuf_ops_t));

    if (pi->ops.mbuf_ctor(pi))
        CNE_ERR_GOTO(leave, "not able to construct pktmbuf_t pool\n");

    /* Call the default buffer initialization routine for each buffer */
    if (pktmbuf_iterate(pi, __mbuf_init, NULL))
        CNE_ERR_GOTO(leave, "initialization of buffers to defaults has failed\n");

    pi_list_lock();
    TAILQ_INSERT_TAIL(&pinfo_list, pi, next);
    pi_list_unlock();

    return pi;
leave:
    pktmbuf_destroy(pi);
    return NULL;
}

pktmbuf_info_t *
pktmbuf_pool_create(char *addr, uint32_t bufcnt, uint32_t bufsz, uint32_t cache_sz, mbuf_ops_t *ops)
{
    pktmbuf_pool_cfg_t cfg = {0};

    /* create a pktmbuf pool configuration structure with no external metadata */
    cfg.addr     = addr;
    cfg.bufcnt   = bufcnt;
    cfg.bufsz    = bufsz;
    cfg.cache_sz = cache_sz;
    cfg.ops      = ops;

    return pktmbuf_pool_cfg_create(&cfg);
}

void
pktmbuf_destroy(pktmbuf_info_t *pi)
{
    if (pi) {
        if (pi->ops.mbuf_dtor)
            pi->ops.mbuf_dtor(pi);

        pi_list_lock();
        TAILQ_REMOVE(&pinfo_list, pi, next);
        pi_list_unlock();

        free(pi);
    }
}

/* do some sanity checks on a mbuf: panic if it fails */
void
pktmbuf_sanity_check(const pktmbuf_t *m, int is_header)
{
    const char *reason;

    if (pktmbuf_check(m, is_header, &reason))
        cne_panic("%s", reason);
}

int
pktmbuf_check(const pktmbuf_t *m, int is_header, const char **reason)
{
    if (m == NULL) {
        *reason = "mbuf is NULL";
        return -1;
    }

    /* generic checks */
    if (m->pooldata == NULL) {
        *reason = "bad pktmbuf pool pointer";
        return -1;
    }
    if (m->buf_addr == NULL) {
        *reason = "bad virt addr";
        return -1;
    }

    uint16_t cnt = pktmbuf_refcnt_read(m);
    if ((cnt == 0) || (cnt == UINT16_MAX)) {
        *reason = "bad ref cnt";
        return -1;
    }

    /* nothing to check for sub-segments */
    if (is_header == 0)
        return 0;

    if (m->data_off > m->buf_len) {
        *reason = "data offset too big in mbuf segment";
        return -1;
    }
    if (m->data_off + m->data_len > m->buf_len) {
        *reason = "data length too big in mbuf segment";
        return -1;
    }

    return 0;
}

/* Create a deep copy of mbuf */
pktmbuf_t *
pktmbuf_copy(const pktmbuf_t *m, pktmbuf_info_t *pi, uint32_t off, uint32_t len)
{
    const pktmbuf_t *seg = m;
    pktmbuf_t *mc;

    /* garbage in check */
    __pktmbuf_sanity_check(m, 1);

    /* check for request to copy at offset past end of mbuf */
    if (unlikely(off >= m->buf_len))
        return NULL;

    mc = pktmbuf_alloc(pi);
    if (unlikely(mc == NULL))
        return NULL;

    /* truncate requested length to available data */
    if (len > m->buf_len - off)
        len = m->buf_len - off;

    __pktmbuf_copy_hdr(mc, m);

    uint32_t copy_len;

    /* current buffer is full, chain a new one */
    if (pktmbuf_tailroom(m) == 0)
        return NULL;

    /*
     * copy the min of data in input segment (seg)
     * vs space available in output (m_last)
     */
    copy_len = CNE_MIN(seg->data_len - off, len);
    if (copy_len > pktmbuf_tailroom(m))
        copy_len = pktmbuf_tailroom(m);

    memcpy(pktmbuf_mtod(mc, char *), pktmbuf_mtod(m, char *), copy_len);

    /* update offsets and lengths */
    mc->data_len = copy_len;

    /* garbage out check */
    __pktmbuf_sanity_check(mc, 1);
    return mc;
}

#define LINE_LEN 256

static void
_hexdump(const char *title, const void *buf, unsigned int len)
{
    unsigned int i, out, ofs;
    const unsigned char *data = buf;
    char line[LINE_LEN]; /* space needed 8+16*3+3+16 == 75 */

    cne_printf("%s at [%p], len=%u\n  ", title ? "" : "  Dump data", data, len);
    ofs = 0;
    while (ofs < len) {
        /* format the line in the buffer */
        out = snprintf(line, LINE_LEN, "%08X:", ofs);
        for (i = 0; i < 16; i++) {
            if (ofs + i < len)
                snprintf(line + out, LINE_LEN - out, " %02X", (data[ofs + i] & 0xff));
            else
                strcpy(line + out, "   ");
            out += 3;
        }

        for (; i <= 16; i++)
            out += snprintf(line + out, LINE_LEN - out, " | ");

        for (i = 0; ofs < len && i < 16; i++, ofs++) {
            unsigned char c = data[ofs];

            if (c < ' ' || c > '~')
                c = '.';
            out += snprintf(line + out, LINE_LEN - out, "%c", c);
        }
        cne_printf("%s\n  ", line);
    }
    cne_printf("\r");
}

/* dump a mbuf on console */
void
pktmbuf_dump(const char *msg, const pktmbuf_t *m, unsigned dump_len)
{
    unsigned int len;

    __pktmbuf_sanity_check(m, 1);

    if (msg)
        cne_printf("[yellow]>>> [orange]%s [yellow]<<<[]\n", msg);
    cne_printf("  dump mbuf at %p, buf_addr %p, data_start %p, pool %p\n", (void *)(uintptr_t)m,
               (void *)m->buf_addr, CNE_PTR_ADD(m->buf_addr, m->data_off), m->pooldata);
    cne_printf("  buf_len=%u, data_off=%u, l2_len %d, l3_len %d, l4_len %d,", (unsigned)m->buf_len,
               (unsigned)m->data_off, m->l2_len, m->l3_len, m->l4_len);
    cne_printf(" data_len=%" PRIu32 ", in_port=%u, refcnt=%d\n", m->data_len, (unsigned)m->lport,
               m->refcnt);
    cne_printf("  tx_offload= 0x%04lx, hash=0x%08x, ptype=%08x, userptr=%p\n", m->tx_offload,
               m->hash, m->packet_type, m->userptr);

    __pktmbuf_sanity_check(m, 0);

    len = dump_len;
    if (len > m->data_len)
        len = m->data_len;
    if (len != 0)
        _hexdump(NULL, pktmbuf_mtod(m, void *), len);
    dump_len -= len;
}

/**
 * Read len data bytes from a mbuf into a buffer using the specified offset.
 *
 * @param m
 *   The pktmbuf_t to copy the data from
 * @param off
 *   The offset to start copying data into the buffer
 * @param len
 *   The number of bytes to copy into the buffer
 * @param buf
 *   The buffer to copy data into and the len must be equal to or greater than buffer size.
 * @return
 *   NULL on error or pointer to start of buffer.
 */
const void *
__pktmbuf_read(const pktmbuf_t *m, uint32_t off, uint32_t len, void *buf)
{
    uint32_t copy_len;

    if (!m || !buf || len == 0)
        return NULL;

    if (off >= pktmbuf_data_len(m))
        return NULL;

    copy_len = pktmbuf_data_len(m) - off;
    if (copy_len > len)
        copy_len = len;

    memcpy((char *)buf, pktmbuf_mtod_offset(m, char *, off), copy_len);

    return buf;
}

/**
 * Write data from a buffer into an mbuf at the given offset
 *
 * @param buf
 *   Source data to copy into the mbuf.
 * @param len
 *   Number of bytes in the buffer to copy to the mbuf, len must be able to
 *   fit in mbuf buffer space.
 * @param
 *   The pktmbuf_t pointer to receive the buffer data using offset value
 * @param off
 *   The offset into the mbuf to start copying the data, can't exceed data length
 * @return
 *   NULL on error or the starting address of the copied data in mbuf
 */
const void *
__pktmbuf_write(const void *buf, uint32_t len, pktmbuf_t *m, uint32_t off)
{
    char *sptr, *lptr, *eptr;

    if (!buf || !m)
        return NULL;

    /* Make sure the offset is within the mbuf data range */
    if (off > pktmbuf_data_len(m))
        return NULL;

    /* Find the starting address to start copying the data */
    sptr = pktmbuf_mtod_offset(m, char *, off);
    if (len == 0)
        return sptr;

    /* Find the last address of the copied data in the mbuf buffer */
    lptr = sptr + len;

    /* determine the end of the mbuf and make sure we do not overrun the end */
    eptr = pktmbuf_mtod_end(m);
    if (lptr >= eptr)
        return NULL;

    /* Determine the last address of the current packet data */
    eptr = pktmbuf_mtod_last(m);

    /* determine if we need to increase or append more space to the mbuf data */
    if (lptr > eptr) {
        /* Increase the packet length to hold the new data */
        if (pktmbuf_append(m, lptr - eptr) == NULL)
            return NULL;
    }

    memcpy(sptr, buf, len);

    return sptr;
}

/* Creates a shallow copy of mbuf */
pktmbuf_t *
pktmbuf_clone(pktmbuf_t *md, pktmbuf_info_t *pi)
{
    pktmbuf_t *mc;

    if (!md) /* pi is checked in the pktmbuf_alloc() path */
        return NULL;

    mc = pktmbuf_alloc(pi);
    if (unlikely(mc == NULL))
        return NULL;

    mc->lport      = md->lport;
    mc->tx_offload = md->tx_offload;
    mc->buf_len    = md->buf_len;
    mc->data_off   = md->data_off;
    mc->data_len   = md->data_len;
    mc->buf_addr   = md->buf_addr;

    return mc;
}

/*
 * Get the name of a RX offload flag. Must be kept synchronized with flag
 * definitions in cne_mbuf.h.
 */
const char *
cne_get_rx_ol_flag_name(uint64_t mask)
{
    // clang-format off
    switch (mask) {
    case CNE_MBUF_F_RX_VLAN:                    return "RX_VLAN";
    case CNE_MBUF_F_RX_RSS_HASH:                return "RX_RSS_HASH";
    case CNE_MBUF_F_RX_FDIR:                    return "RX_FDIR";
    case CNE_MBUF_F_RX_L4_CKSUM_BAD:            return "RX_L4_CKSUM_BAD";
    case CNE_MBUF_F_RX_L4_CKSUM_GOOD:           return "RX_L4_CKSUM_GOOD";
    case CNE_MBUF_F_RX_L4_CKSUM_NONE:           return "RX_L4_CKSUM_NONE";
    case CNE_MBUF_F_RX_IP_CKSUM_BAD:            return "RX_IP_CKSUM_BAD";
    case CNE_MBUF_F_RX_IP_CKSUM_GOOD:           return "RX_IP_CKSUM_GOOD";
    case CNE_MBUF_F_RX_IP_CKSUM_NONE:           return "RX_IP_CKSUM_NONE";
    case CNE_MBUF_F_RX_OUTER_IP_CKSUM_BAD:      return "RX_OUTER_IP_CKSUM_BAD";
    case CNE_MBUF_F_RX_VLAN_STRIPPED:           return "RX_VLAN_STRIPPED";
    case CNE_MBUF_F_RX_IEEE1588_PTP:            return "RX_IEEE1588_PTP";
    case CNE_MBUF_F_RX_IEEE1588_TMST:           return "RX_IEEE1588_TMST";
    case CNE_MBUF_F_RX_FDIR_ID:                 return "RX_FDIR_ID";
    case CNE_MBUF_F_RX_FDIR_FLX:                return "RX_FDIR_FLX";
    case CNE_MBUF_F_RX_QINQ_STRIPPED:           return "RX_QINQ_STRIPPED";
    case CNE_MBUF_F_RX_QINQ:                    return "RX_QINQ";
    case CNE_MBUF_F_RX_LRO:                     return "RX_LRO";
    case CNE_MBUF_F_RX_SEC_OFFLOAD:             return "RX_SEC_OFFLOAD";
    case CNE_MBUF_F_RX_SEC_OFFLOAD_FAILED:      return "RX_SEC_OFFLOAD_FAILED";
    case CNE_MBUF_F_RX_OUTER_L4_CKSUM_BAD:      return "RX_OUTER_L4_CKSUM_BAD";
    case CNE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD:     return "RX_OUTER_L4_CKSUM_GOOD";
    case CNE_MBUF_F_RX_OUTER_L4_CKSUM_INVALID:  return "RX_OUTER_L4_CKSUM_INVALID";

    default: return NULL;
    }
    // clang-format on
}

struct flag_mask {
    uint64_t flag;
    uint64_t mask;
    const char *default_name;
};

/* write the list of rx ol flags in buffer buf */
int
cne_get_rx_ol_flag_list(uint64_t mask, char *buf, size_t buflen)
{
    // clang-format off
    const struct flag_mask rx_flags[] = {
        { CNE_MBUF_F_RX_VLAN, CNE_MBUF_F_RX_VLAN, NULL },
        { CNE_MBUF_F_RX_RSS_HASH, CNE_MBUF_F_RX_RSS_HASH, NULL },
        { CNE_MBUF_F_RX_FDIR, CNE_MBUF_F_RX_FDIR, NULL },
        { CNE_MBUF_F_RX_L4_CKSUM_BAD, CNE_MBUF_F_RX_L4_CKSUM_MASK, NULL },
        { CNE_MBUF_F_RX_L4_CKSUM_GOOD, CNE_MBUF_F_RX_L4_CKSUM_MASK, NULL },
        { CNE_MBUF_F_RX_L4_CKSUM_NONE, CNE_MBUF_F_RX_L4_CKSUM_MASK, NULL },
        { CNE_MBUF_F_RX_L4_CKSUM_UNKNOWN, CNE_MBUF_F_RX_L4_CKSUM_MASK, "RX_L4_CKSUM_UNKNOWN" },
        { CNE_MBUF_F_RX_IP_CKSUM_BAD, CNE_MBUF_F_RX_IP_CKSUM_MASK, NULL },
        { CNE_MBUF_F_RX_IP_CKSUM_GOOD, CNE_MBUF_F_RX_IP_CKSUM_MASK, NULL },
        { CNE_MBUF_F_RX_IP_CKSUM_NONE, CNE_MBUF_F_RX_IP_CKSUM_MASK, NULL },
        { CNE_MBUF_F_RX_IP_CKSUM_UNKNOWN, CNE_MBUF_F_RX_IP_CKSUM_MASK, "RX_IP_CKSUM_UNKNOWN" },
        { CNE_MBUF_F_RX_OUTER_IP_CKSUM_BAD, CNE_MBUF_F_RX_OUTER_IP_CKSUM_BAD, NULL },
        { CNE_MBUF_F_RX_VLAN_STRIPPED, CNE_MBUF_F_RX_VLAN_STRIPPED, NULL },
        { CNE_MBUF_F_RX_IEEE1588_PTP, CNE_MBUF_F_RX_IEEE1588_PTP, NULL },
        { CNE_MBUF_F_RX_IEEE1588_TMST, CNE_MBUF_F_RX_IEEE1588_TMST, NULL },
        { CNE_MBUF_F_RX_FDIR_ID, CNE_MBUF_F_RX_FDIR_ID, NULL },
        { CNE_MBUF_F_RX_FDIR_FLX, CNE_MBUF_F_RX_FDIR_FLX, NULL },
        { CNE_MBUF_F_RX_QINQ_STRIPPED, CNE_MBUF_F_RX_QINQ_STRIPPED, NULL },
        { CNE_MBUF_F_RX_LRO, CNE_MBUF_F_RX_LRO, NULL },
        { CNE_MBUF_F_RX_SEC_OFFLOAD, CNE_MBUF_F_RX_SEC_OFFLOAD, NULL },
        { CNE_MBUF_F_RX_SEC_OFFLOAD_FAILED, CNE_MBUF_F_RX_SEC_OFFLOAD_FAILED, NULL },
        { CNE_MBUF_F_RX_QINQ, CNE_MBUF_F_RX_QINQ, NULL },
        { CNE_MBUF_F_RX_OUTER_L4_CKSUM_BAD, CNE_MBUF_F_RX_OUTER_L4_CKSUM_MASK, NULL },
        { CNE_MBUF_F_RX_OUTER_L4_CKSUM_GOOD, CNE_MBUF_F_RX_OUTER_L4_CKSUM_MASK, NULL },
        { CNE_MBUF_F_RX_OUTER_L4_CKSUM_INVALID, CNE_MBUF_F_RX_OUTER_L4_CKSUM_MASK, NULL },
        { CNE_MBUF_F_RX_OUTER_L4_CKSUM_UNKNOWN, CNE_MBUF_F_RX_OUTER_L4_CKSUM_MASK, "RX_OUTER_L4_CKSUM_UNKNOWN" },
    };
    // clang-format off
    const char *name;
    unsigned int i;
    int ret;

    if (buflen == 0)
        return -1;

    buf[0] = '\0';
    for (i = 0; i < CNE_DIM(rx_flags); i++) {
        if ((mask & rx_flags[i].mask) != rx_flags[i].flag)
            continue;
        name = cne_get_rx_ol_flag_name(rx_flags[i].flag);
        if (name == NULL)
            name = rx_flags[i].default_name;
        ret = snprintf(buf, buflen, "%s ", name);
        if (ret < 0)
            return -1;
        if ((size_t)ret >= buflen)
            return -1;
        buf += ret;
        buflen -= ret;
    }

    return 0;
}

/*
 * Get the name of a TX offload flag. Must be kept synchronized with flag
 * definitions in cne_mbuf.h.
 */
const char *
cne_get_tx_ol_flag_name(uint64_t mask)
{
    // clang-format off
    switch (mask) {
    case CNE_MBUF_F_TX_VLAN:                return "TX_VLAN";
    case CNE_MBUF_F_TX_IP_CKSUM:            return "TX_IP_CKSUM";
    case CNE_MBUF_F_TX_TCP_CKSUM:           return "TX_TCP_CKSUM";
    case CNE_MBUF_F_TX_SCTP_CKSUM:          return "TX_SCTP_CKSUM";
    case CNE_MBUF_F_TX_UDP_CKSUM:           return "TX_UDP_CKSUM";
    case CNE_MBUF_F_TX_IEEE1588_TMST:       return "TX_IEEE1588_TMST";
    case CNE_MBUF_F_TX_TCP_SEG:             return "TX_TCP_SEG";
    case CNE_MBUF_F_TX_IPV4:                return "TX_IPV4";
    case CNE_MBUF_F_TX_IPV6:                return "TX_IPV6";
    case CNE_MBUF_F_TX_OUTER_IP_CKSUM:      return "TX_OUTER_IP_CKSUM";
    case CNE_MBUF_F_TX_OUTER_IPV4:          return "TX_OUTER_IPV4";
    case CNE_MBUF_F_TX_OUTER_IPV6:          return "TX_OUTER_IPV6";
    case CNE_MBUF_F_TX_TUNNEL_VXLAN:        return "TX_TUNNEL_VXLAN";
    case CNE_MBUF_F_TX_TUNNEL_GTP:          return "TX_TUNNEL_GTP";
    case CNE_MBUF_F_TX_TUNNEL_GRE:          return "TX_TUNNEL_GRE";
    case CNE_MBUF_F_TX_TUNNEL_IPIP:         return "TX_TUNNEL_IPIP";
    case CNE_MBUF_F_TX_TUNNEL_GENEVE:       return "TX_TUNNEL_GENEVE";
    case CNE_MBUF_F_TX_TUNNEL_MPLSINUDP:    return "TX_TUNNEL_MPLSINUDP";
    case CNE_MBUF_F_TX_TUNNEL_VXLAN_GPE:    return "TX_TUNNEL_VXLAN_GPE";
    case CNE_MBUF_F_TX_TUNNEL_IP:           return "TX_TUNNEL_IP";
    case CNE_MBUF_F_TX_TUNNEL_UDP:          return "TX_TUNNEL_UDP";
    case CNE_MBUF_F_TX_QINQ:                return "TX_QINQ";
    case CNE_MBUF_F_TX_MACSEC:              return "TX_MACSEC";
    case CNE_MBUF_F_TX_SEC_OFFLOAD:         return "TX_SEC_OFFLOAD";
    case CNE_MBUF_F_TX_UDP_SEG:             return "TX_UDP_SEG";
    case CNE_MBUF_F_TX_OUTER_UDP_CKSUM:     return "TX_OUTER_UDP_CKSUM";
    case CNE_MBUF_TYPE_MCAST:               return "MBUF_TYPE_MCAST";
    case CNE_MBUF_TYPE_BCAST:               return "MBUF_TYPE_BCAST";
    case CNE_MBUF_TYPE_IPv6:                return "MBUF_TYPE_IPv6";
    default: return NULL;
    }
    // clang-format on
}

/* write the list of tx ol flags in buffer buf */
int
cne_get_tx_ol_flag_list(uint64_t mask, char *buf, size_t buflen)
{
    // clang-format off
    const struct flag_mask tx_flags[] = {
        { CNE_MBUF_F_TX_VLAN, CNE_MBUF_F_TX_VLAN, NULL },
        { CNE_MBUF_F_TX_IP_CKSUM, CNE_MBUF_F_TX_IP_CKSUM, NULL },
        { CNE_MBUF_F_TX_TCP_CKSUM, CNE_MBUF_F_TX_L4_MASK, NULL },
        { CNE_MBUF_F_TX_SCTP_CKSUM, CNE_MBUF_F_TX_L4_MASK, NULL },
        { CNE_MBUF_F_TX_UDP_CKSUM, CNE_MBUF_F_TX_L4_MASK, NULL },
        { CNE_MBUF_F_TX_L4_NO_CKSUM, CNE_MBUF_F_TX_L4_MASK, "CNE_MBUF_F_TX_L4_NO_CKSUM" },
        { CNE_MBUF_F_TX_IEEE1588_TMST, CNE_MBUF_F_TX_IEEE1588_TMST, NULL },
        { CNE_MBUF_F_TX_TCP_SEG, CNE_MBUF_F_TX_TCP_SEG, NULL },
        { CNE_MBUF_F_TX_IPV4, CNE_MBUF_F_TX_IPV4, NULL },
        { CNE_MBUF_F_TX_IPV6, CNE_MBUF_F_TX_IPV6, NULL },
        { CNE_MBUF_F_TX_OUTER_IP_CKSUM, CNE_MBUF_F_TX_OUTER_IP_CKSUM, NULL },
        { CNE_MBUF_F_TX_OUTER_IPV4, CNE_MBUF_F_TX_OUTER_IPV4, NULL },
        { CNE_MBUF_F_TX_OUTER_IPV6, CNE_MBUF_F_TX_OUTER_IPV6, NULL },
        { CNE_MBUF_F_TX_TUNNEL_VXLAN, CNE_MBUF_F_TX_TUNNEL_MASK, NULL },
        { CNE_MBUF_F_TX_TUNNEL_GTP, CNE_MBUF_F_TX_TUNNEL_MASK, NULL },
        { CNE_MBUF_F_TX_TUNNEL_GRE, CNE_MBUF_F_TX_TUNNEL_MASK, NULL },
        { CNE_MBUF_F_TX_TUNNEL_IPIP, CNE_MBUF_F_TX_TUNNEL_MASK, NULL },
        { CNE_MBUF_F_TX_TUNNEL_GENEVE, CNE_MBUF_F_TX_TUNNEL_MASK, NULL },
        { CNE_MBUF_F_TX_TUNNEL_MPLSINUDP, CNE_MBUF_F_TX_TUNNEL_MASK, NULL },
        { CNE_MBUF_F_TX_TUNNEL_VXLAN_GPE, CNE_MBUF_F_TX_TUNNEL_MASK, NULL },
        { CNE_MBUF_F_TX_TUNNEL_IP, CNE_MBUF_F_TX_TUNNEL_MASK, NULL },
        { CNE_MBUF_F_TX_TUNNEL_UDP, CNE_MBUF_F_TX_TUNNEL_MASK, NULL },
        { CNE_MBUF_F_TX_QINQ, CNE_MBUF_F_TX_QINQ, NULL },
        { CNE_MBUF_F_TX_MACSEC, CNE_MBUF_F_TX_MACSEC, NULL },
        { CNE_MBUF_F_TX_SEC_OFFLOAD, CNE_MBUF_F_TX_SEC_OFFLOAD, NULL },
        { CNE_MBUF_F_TX_UDP_SEG, CNE_MBUF_F_TX_UDP_SEG, NULL },
        { CNE_MBUF_F_TX_OUTER_UDP_CKSUM, CNE_MBUF_F_TX_OUTER_UDP_CKSUM, NULL },
        { CNE_MBUF_TYPE_MCAST, CNE_MBUF_TYPE_MCAST, NULL },
        { CNE_MBUF_TYPE_BCAST, CNE_MBUF_TYPE_BCAST, NULL },
        { CNE_MBUF_TYPE_IPv6, CNE_MBUF_TYPE_IPv6, NULL },
    };
    // clang-format on
    const char *name;
    unsigned int i;
    int ret;

    if (buflen == 0)
        return -1;

    buf[0] = '\0';
    for (i = 0; i < CNE_DIM(tx_flags); i++) {
        if ((mask & tx_flags[i].mask) != tx_flags[i].flag)
            continue;
        name = cne_get_tx_ol_flag_name(tx_flags[i].flag);
        if (name == NULL)
            name = tx_flags[i].default_name;
        ret = snprintf(buf, buflen, "%s ", name);
        if (ret < 0)
            return -1;
        if ((size_t)ret >= buflen)
            return -1;
        buf += ret;
        buflen -= ret;
    }

    return 0;
}

static void
__info_dump(pktmbuf_info_t *pi)
{
    const char *name = (pi->name[0] == '\0') ? "Unknown" : pi->name;

    cne_printf(
        "[orange]%-16s [magenta]mbufs[]: [cyan]%p [magenta]bufcnt[]: [cyan]%'d [magenta]bufsz[]: "
        "[cyan]%'d [magenta]cache[]: [cyan]%'d [magenta]pool[]: [cyan]%p[]\n  ",
        name, pi->addr, pi->bufcnt, pi->bufsz, pi->cache_sz, pi->pd);
    if (pi->pd)
        mempool_dump(pi->pd);
}

void
pktmbuf_info_dump(void)
{
    pktmbuf_info_t *pi;

    pi_list_lock();
    TAILQ_FOREACH (pi, &pinfo_list, next) {
        __info_dump(pi);
    }
    pi_list_unlock();
}

CNE_INIT_PRIO(pinfo_constructor, START)
{
    TAILQ_INIT(&pinfo_list);

    if (cne_mutex_create(&pinfo_list_mutex, PTHREAD_MUTEX_RECURSIVE) < 0)
        CNE_RET("mutex init(pinfo_list_mutex) failed\n");
}
