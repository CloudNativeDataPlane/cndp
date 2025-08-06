/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2025 Intel Corp, Inc.
 */
#include <stdio.h>             // for EOF, NULL
#include <stdint.h>            // for uint32_t
#include <tst_info.h>          // for tst_error, tst_ok, tst_end, tst_start, TST_F...
#include <cne_common.h>        // for CNE_SET_USED
#include <getopt.h>            // for getopt_long, option
#include <cne_log.h>           // for cne_log, cne_log_set_level, CNE_LOG_INFO

#include "log_test.h"
#include "cne_stdio.h"        // for cne_printf

#define LEV_NUM 8

static int
log_test(void)
{
    uint32_t log_level[] = {CNE_LOG_EMERG,   CNE_LOG_ALERT,  CNE_LOG_CRIT, CNE_LOG_ERR,
                            CNE_LOG_WARNING, CNE_LOG_NOTICE, CNE_LOG_INFO, CNE_LOG_DEBUG};
    cne_printf("\n[blue]>>>[white]TEST: CNE Log Level test started \n");
    for (int i = 0; i < LEV_NUM; i++) {
        cne_log_set_level(log_level[i]);
        if (cne_log_get_level() != log_level[i]) {
            tst_error("Fail --- TEST: Set CNE_LOG level failed\n");
            goto leave;
        }
    }
    tst_ok("PASS --- TEST: Set CNE_LOG level Pass\n");

    cne_printf("\n[blue]>>>[white]TEST: cne_log test started \n");
    cne_log_set_level(CNE_LOG_INFO);
    int output;
    output = cne_log(CNE_LOG_DEBUG, __func__, __LINE__, "The log of func: %s in line: %d \n",
                     __func__, __LINE__);
    if (output > 0) {
        tst_error("Fail --- TEST: Set CNE_LOG failed\n");
        goto leave;
    }
    output = cne_log(CNE_LOG_INFO, __func__, __LINE__, "The log of func: %s in line: %d \n",
                     __func__, __LINE__);
    if (output <= 0) {
        tst_error("Fail --- TEST: Set CNE_LOG failed\n");
        goto leave;
    }
    tst_ok("PASS --- TEST: Set CNE_LOG output Pass\n");

    cne_printf("\n[blue]>>>[white]TEST: cne_print test started \n");
    output = cne_print("The log of func: %s in line: %d \n", __func__, __LINE__);
    if (output <= 0) {
        tst_error("Fail --- TEST: Set CNE_LOG failed\n");
        goto leave;
    }
    tst_ok("PASS --- TEST: Set cne_print Pass\n");

    cne_printf("\n[blue]>>>[white]TEST: cne_dump_stack test started \n");
    cne_dump_stack();
    tst_ok("PASS --- TEST: Set cne_dump_stack Pass\n");

    return 0;
leave:
    return -1;
}

int
log_main(int argc, char **argv)
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

    tst = tst_start("LOG");

    if (log_test() < 0)
        goto err;

    tst_end(tst, TST_PASSED);
    return 0;
err:
    tst_end(tst, TST_FAILED);
    return -1;
}
