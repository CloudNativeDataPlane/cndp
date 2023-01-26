/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Intel Corporation.
 */

#include <cne_strings.h>          // for cne_strtok
#include <net/cne_ether.h>        // for ether_addr
#include <txbuff.h>               // for txbuff_add, txbuff_t
#include <cne_log.h>              // for CNE_ERR_RET, CNE_LOG_ERR

#include "main.h"

#ifdef ENABLE_HYPERSCAN
/*
 * This is the event handler callback for hyperscan. The ID value is encoded into two
 * 16 bits values. The upper 16 bits is the destination lport ID and flags with the lower 16 bits
 * is the unique ID value to make sure all of the Hyperscan IDs are unique values.
 *
 * This routine returns a 16 bit value pointed to by ctx, which is bits 16-31 of the ID value.
 * For the hyperscan forwarding code to work the bits 16-23 define the lport ID and
 * if bit 15 0x8000 of these 16 bits is set then the packet is dropped and not forwarded.
 */
static int
hsfwd_handler(unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags,
              void *ctx)
{
    uint16_t *lport = ctx;

    CNE_SET_USED(from);
    CNE_SET_USED(to);
    CNE_SET_USED(flags);

    /* return bits 16-31 a 16 bit value using pointer to lport */
    if (lport)
        *lport = (uint16_t)(id >> 16);

    return 0;
}
#endif /* ENABLE_HYPERSCAN */

int
hsfwd_test(jcfg_lport_t *lport, struct fwd_info *fwd)
{
#ifdef ENABLE_HYPERSCAN
    /* do we forward non-matching packets? */
    struct fwd_port *pd                          = lport->priv_;
    struct create_txbuff_thd_priv_t *thd_private = pd->thd->priv_;
    uint16_t n_pkts;
    txbuff_t **txbuff;

    if (!pd)
        return -1;

    txbuff = thd_private->txbuffs;

    if (!thd_private->scratch)
        if (hs_clone_scratch(fwd->hs_scratch, &thd_private->scratch) != HS_SUCCESS)
            return -1;

    /* receive buffers from the network */
    switch (fwd->pkt_api) {
    case XSKDEV_PKT_API:
        n_pkts = xskdev_rx_burst(pd->xsk, (void **)pd->rx_mbufs, BURST_SIZE);
        break;
    case PKTDEV_PKT_API:
        n_pkts = pktdev_rx_burst(pd->lport, pd->rx_mbufs, BURST_SIZE);
        if (n_pkts == PKTDEV_ADMIN_STATE_DOWN) {
            hs_free_scratch(thd_private->scratch);
            thd_private->scratch = NULL;
            return 0;
        }
        break;
    default:
        n_pkts = 0;
        break;
    }

    for (int i = 0; i < n_pkts; i++) {
        pktmbuf_t *pkt = pd->rx_mbufs[i];
        uint16_t dst_lport;
        jcfg_lport_t *dst;

        dst_lport = 0x8000; /* indicates a packet does not match any expressions, drop it */
        if (hs_scan(fwd->hs_database, pktmbuf_mtod(pkt, char *), pktmbuf_data_len(pkt), 0,
                    thd_private->scratch, hsfwd_handler, &dst_lport) != HS_SUCCESS) {
            hs_free_scratch(thd_private->scratch);
            thd_private->scratch = NULL;
            return -1;
        }

        if (dst_lport & 0x8000) {
            pktmbuf_free(pkt);
            continue;
        }

        dst = jcfg_lport_by_index(fwd->jinfo, (dst_lport & 0xFF));
        if (!dst)
            /* Cannot forward to non-existing port, so echo back on incoming interface */
            dst = lport;

        MAC_SWAP(pktmbuf_mtod(pkt, void *));
        (void)txbuff_add(txbuff[dst->lpid], pkt);
    }

    int nb_lports = jcfg_num_lports(fwd->jinfo);
    for (int i = 0; i < nb_lports; i++) {
        jcfg_lport_t *dst = jcfg_lport_by_index(fwd->jinfo, i);

        if (!dst)
            continue;

        /* Could hang here if we can never flush the TX packets */
        while (txbuff_count(txbuff[dst->lpid]) > 0)
            txbuff_flush(txbuff[dst->lpid]);
    }

    hs_free_scratch(thd_private->scratch);
    thd_private->scratch = NULL;
    return 0;
#else
    CNE_SET_USED(lport);
    CNE_SET_USED(fwd);
    return -1;
#endif /* ENABLE HYPERSCAN */
}

#ifdef ENABLE_HYPERSCAN
static unsigned
hs_parse_flags(const char *str)
{
    unsigned flags = 0;

    if (!str)
        return flags;

    for (; *str != '\0'; str++) {
        switch (*str) {
        case 'i':
            flags |= HS_FLAG_CASELESS;
            break;
        case 'm':
            flags |= HS_FLAG_MULTILINE;
            break;
        case 's':
            flags |= HS_FLAG_DOTALL;
            break;
        case 'H':
            flags |= HS_FLAG_SINGLEMATCH;
            break;
        case 'V':
            flags |= HS_FLAG_ALLOWEMPTY;
            break;
        case '8':
            flags |= HS_FLAG_UTF8;
            break;
        case 'W':
            flags |= HS_FLAG_UCP;
            break;
        case '\r':        // stray carriage-return
            break;
        case '\n':        // stray newline
            break;
        default:
            cne_printf("Unsupported flag \'%c'\n", *str);
            exit(-1);
        }
    }
    return flags;
}

static int
process_patterns(struct fwd_info *fwd)
{
    char *entries[4];
    unsigned int id;

    fwd->hs_ids         = (unsigned int *)calloc(fwd->hs_pattern_count + 1, sizeof(unsigned int));
    fwd->hs_expressions = calloc(fwd->hs_pattern_count + 1, sizeof(char *));
    fwd->hs_flags       = (unsigned int *)calloc(fwd->hs_pattern_count + 1, sizeof(unsigned int));
    if (!fwd->hs_expressions || !fwd->hs_flags || !fwd->hs_ids) {
        free(fwd->hs_ids);
        free((void *)(uintptr_t)fwd->hs_expressions);
        free(fwd->hs_flags);
        return -1;
    }

    for (int i = 0; i < fwd->hs_pattern_count; i++) {
        char saved[128];
        int n;

        /* Save a copy of the original string for errors */
        memset(saved, 0, sizeof(saved)); /* make sure we have a NULL terminated string */
        strncpy(saved, fwd->hs_patterns[i], sizeof(saved) - 1);

        n = cne_strtok(fwd->hs_patterns[i], "/", entries, cne_countof(entries));

        if (n < 2 || n > 3)
            CNE_ERR_RET("Hyperscan pattern count '%s' is invalid\n", saved);

        if (entries[0] == NULL)
            CNE_ERR_RET("Hyperscan pattern ID '%s' is invalid\n", saved);
        errno = 0;
        id    = strtoul(entries[0], NULL, 0);
        if (errno)
            CNE_ERR_RET("Hyperscan ID in pattern '%s' is invalid: %s\n", saved, strerror(errno));
        fwd->hs_ids[i]         = id;
        fwd->hs_expressions[i] = entries[1];
        fwd->hs_flags[i]       = hs_parse_flags(entries[2]);
        CNE_DEBUG("ID:0x%08x, Flags:0x%08x, Pattern:%s\n", fwd->hs_ids[i], fwd->hs_flags[i],
                  fwd->hs_expressions[i]);
    }

    return 0;
}
#endif /* ENABLE HYPERSCAN */

void
hsfwd_finish(struct fwd_info *fwd)
{
#ifdef ENABLE_HYPERSCAN
    if (!fwd)
        return;

    free(fwd->hs_ids);
    free(fwd->hs_expressions);
    free(fwd->hs_flags);
    fwd->hs_ids         = NULL;
    fwd->hs_expressions = NULL;
    fwd->hs_flags       = NULL;

    hs_free_database(fwd->hs_database);
    hs_free_scratch(fwd->hs_scratch);
    fwd->hs_database = NULL;
    fwd->hs_scratch  = NULL;
#else
    CNE_SET_USED(fwd);
#endif /* ENABLE HYPERSCAN */
}

int
hsfwd_init(struct fwd_info *fwd)
{
#ifdef ENABLE_HYPERSCAN
    hs_compile_error_t *compile_err;

    if (process_patterns(fwd) < 0)
        return -1;

    if (hs_compile_multi((const char *const *)fwd->hs_expressions, fwd->hs_flags, fwd->hs_ids,
                         fwd->hs_pattern_count, HS_MODE_BLOCK, NULL, &fwd->hs_database,
                         &compile_err) != HS_SUCCESS) {
        cne_printf("[red]ERROR[]: Unable to compile patterns: %s\n", compile_err->message);
        hs_free_compile_error(compile_err);
        return -1;
    }
    free(fwd->hs_ids);
    free((void *)(uintptr_t)fwd->hs_expressions);
    free(fwd->hs_flags);
    fwd->hs_ids         = NULL;
    fwd->hs_expressions = NULL;
    fwd->hs_flags       = NULL;

    fwd->hs_scratch = NULL;
    if (hs_alloc_scratch(fwd->hs_database, &fwd->hs_scratch) != HS_SUCCESS) {
        if (hs_free_database(fwd->hs_database) != HS_SUCCESS)
            cne_printf("hs_free_database() failed\n");
        return -1;
    }
#else
    CNE_SET_USED(fwd);
    CNE_ERR("Not supported, Hyperscan needs to be installed\n");
#endif /* ENABLE HYPERSCAN */
    return 0;
}
