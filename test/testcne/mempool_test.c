/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
 */

// IWYU pragma: no_include <bits/getopt_core.h>

#include <stdio.h>             // for NULL, EOF
#include <stdlib.h>            // for rand
#include <getopt.h>            // for getopt_long, option
#include <cne_common.h>        // for cne_countof
#include <mempool.h>           // for mempool_destroy, mempool_cfg, mempool_...
#include <tst_info.h>          // for tst_error, tst_ok, tst_end, tst_start
#include <cne_mmap.h>          // for mmap_free, mmap_addr, mmap_alloc, MMAP...

#include "mempool_test.h"
#include "cne_stdio.h"        // for cne_printf
#include "vt100_out.h"        // for vt_color, VT_NO_CHANGE, VT_OFF, VT_BLUE

#define MAX_OBJ 4096
typedef struct {
    struct mempool_cfg cinfo;
    int err_type;
} mempools_t;

enum { OK = 0, ERR };

int
mempool_main(int argc, char **argv)
{
    mempool_t *mp;
    void *objs[MAX_OBJ];
    int verbose = 0;

    // clang-format off
    mempools_t *ps, pools[] = {
        {{.objcnt = 1024, .objsz = 512, .cache_sz = 0}, OK},
        {{.objcnt = 2048, .objsz = 1024, .cache_sz = 64}, OK},
        {{.objcnt = 2048, .objsz = 1024, .cache_sz = 64}, OK},
        {{.objcnt = 4096, .objsz = 2048, .cache_sz = 128}, OK},
        {{0}, 0}
    };
    // clang-format on

    tst_info_t *tst;
    int i, ret, n, opt;
    char **argvopt;
    int option_index;
    struct mempool_cfg *ci;
    mmap_t *mm                          = NULL;
    static const struct option lgopts[] = {{NULL, 0, 0, 0}};

    argvopt = argv;

    optind = 0;
    while ((opt = getopt_long(argc, argvopt, "V", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'V':
            verbose = 1;
            break;
        default:
            break;
        }
    }

    tst = tst_start("Mempool");

    for (i = 0; i < cne_countof(pools); i++) {
        ps = &pools[i];
        ci = &ps->cinfo;

        if (ci->objcnt == 0)
            break;

        tst_ok("%d: mempool cnt %5d, sz %5d, cache_size %5d\n", i, ci->objcnt, ci->objsz,
               ci->cache_sz);
        mm = mmap_alloc(ci->objcnt, ci->objsz, MMAP_HUGEPAGE_DEFAULT);
        if (!mm) {
            tst_error("%d: Fail to mmap_alloc(%ld)\n", ci->objcnt * ci->objsz);
            goto err;
        }
        ci->addr = mmap_addr(mm);

        mp = mempool_create(ci);
        if (!mp && ps->err_type == OK) {
            tst_error("%d: Failed to create mempool\n", i);
            goto err;
        }

        ret = mempool_objcnt(mp);
        if (ret != -1 && ret == (int)ci->objcnt)
            tst_ok("PASS --- TEST: Mempool obj count test pass\n");
        else {
            mempool_destroy(mp);
            tst_error("mempool obj count isn't correct");
            goto err;
        }

        mempool_get_bulk(mp, objs, (int)ci->objcnt);
        ret = mempool_empty(mp);
        if (ret == 0) {
            mempool_destroy(mp);
            tst_error("mempool empty status checking failed \n");
            goto err;
        } else
            tst_ok("PASS --- TEST: Mempool empty status test pass\n");

        mempool_put_bulk(mp, objs, (int)ci->objcnt);
        ret = mempool_full(mp);
        if (ret == 0) {
            mempool_destroy(mp);
            tst_error("mempool full status checking failed \n");
            goto err;
        } else
            tst_ok("PASS --- TEST: Mempool full status test pass\n");

        n   = rand() % (ci->objcnt);
        ret = mempool_get_bulk(mp, objs, n);
        if (ret) {
            mempool_destroy(mp);
            tst_error("%d: mempool_get_bulk(%d) failed %d\n", i, n, ret);
            goto err;
        }

        mempool_put_bulk(mp, objs, n);

        if (verbose) {
            vt_color(VT_BLUE, VT_NO_CHANGE, VT_OFF);
            mempool_dump(mp);
            vt_color(VT_DEFAULT_FG, VT_NO_CHANGE, VT_OFF);
            cne_printf("\n");
        }

        mempool_destroy(mp);
        mmap_free(mm);
    }

    tst_end(tst, TST_PASSED);
    return 0;

err:
    mmap_free(mm);
    tst_end(tst, TST_FAILED);
    return -1;
}
