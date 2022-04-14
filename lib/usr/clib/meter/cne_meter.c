/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2022 Intel Corporation
 */

#include <stdio.h>             // for NULL
#include <math.h>              // for ceil
#include <cne_cycles.h>        // for cne_rdtsc
#include <errno.h>             // for EINVAL

#include "cne_meter.h"
#include "cne_system.h"        // for cne_get_timer_hz

#ifndef CNE_METER_TB_PERIOD_MIN
#define CNE_METER_TB_PERIOD_MIN 100
#endif

static void
cne_meter_get_tb_params(uint64_t hz, uint64_t rate, uint64_t *tb_period,
                        uint64_t *tb_bytes_per_period)
{
    double period;

    if (rate == 0) {
        *tb_bytes_per_period = 0;
        *tb_period           = CNE_METER_TB_PERIOD_MIN;
        return;
    }

    period = ((double)hz) / ((double)rate);

    if (period >= CNE_METER_TB_PERIOD_MIN) {
        *tb_bytes_per_period = 1;
        *tb_period           = (uint64_t)period;
    } else {
        *tb_bytes_per_period = (uint64_t)ceil(CNE_METER_TB_PERIOD_MIN / period);
        *tb_period           = (hz * (*tb_bytes_per_period)) / rate;
    }
}

int
cne_meter_srtcm_profile_config(struct cne_meter_srtcm_profile *p,
                               struct cne_meter_srtcm_params *params)
{
    uint64_t hz = cne_get_timer_hz();

    /* Check input parameters */
    if ((p == NULL) || (params == NULL) || (params->cir == 0) ||
        ((params->cbs == 0) && (params->ebs == 0)))
        return -EINVAL;

    /* Initialize srTCM run-time structure */
    p->cbs = params->cbs;
    p->ebs = params->ebs;
    cne_meter_get_tb_params(hz, params->cir, &p->cir_period, &p->cir_bytes_per_period);

    return 0;
}

int
cne_meter_srtcm_config(struct cne_meter_srtcm *m, struct cne_meter_srtcm_profile *p)
{
    /* Check input parameters */
    if ((m == NULL) || (p == NULL))
        return -EINVAL;

    /* Initialize srTCM run-time structure */
    m->time = cne_rdtsc();
    m->tc   = p->cbs;
    m->te   = p->ebs;

    return 0;
}

int
cne_meter_trtcm_profile_config(struct cne_meter_trtcm_profile *p,
                               struct cne_meter_trtcm_params *params)
{
    uint64_t hz = cne_get_timer_hz();

    /* Check input parameters */
    if ((p == NULL) || (params == NULL) || (params->cir == 0) || (params->pir == 0) ||
        (params->pir < params->cir) || (params->cbs == 0) || (params->pbs == 0))
        return -EINVAL;

    /* Initialize trTCM run-time structure */
    p->cbs = params->cbs;
    p->pbs = params->pbs;
    cne_meter_get_tb_params(hz, params->cir, &p->cir_period, &p->cir_bytes_per_period);
    cne_meter_get_tb_params(hz, params->pir, &p->pir_period, &p->pir_bytes_per_period);

    return 0;
}

int
cne_meter_trtcm_config(struct cne_meter_trtcm *m, struct cne_meter_trtcm_profile *p)
{
    /* Check input parameters */
    if ((m == NULL) || (p == NULL))
        return -EINVAL;

    /* Initialize trTCM run-time structure */
    m->time_tc = m->time_tp = cne_rdtsc();
    m->tc                   = p->cbs;
    m->tp                   = p->pbs;

    return 0;
}

int
cne_meter_trtcm_rfc4115_profile_config(struct cne_meter_trtcm_rfc4115_profile *p,
                                       struct cne_meter_trtcm_rfc4115_params *params)
{
    uint64_t hz = cne_get_timer_hz();

    /* Check input parameters */
    if ((p == NULL) || (params == NULL) || (params->cir != 0 && params->cbs == 0) ||
        (params->eir != 0 && params->ebs == 0))
        return -EINVAL;

    /* Initialize trTCM run-time structure */
    p->cbs = params->cbs;
    p->ebs = params->ebs;
    cne_meter_get_tb_params(hz, params->cir, &p->cir_period, &p->cir_bytes_per_period);
    cne_meter_get_tb_params(hz, params->eir, &p->eir_period, &p->eir_bytes_per_period);

    return 0;
}

int
cne_meter_trtcm_rfc4115_config(struct cne_meter_trtcm_rfc4115 *m,
                               struct cne_meter_trtcm_rfc4115_profile *p)
{
    /* Check input parameters */
    if ((m == NULL) || (p == NULL))
        return -EINVAL;

    /* Initialize trTCM run-time structure */
    m->time_tc = m->time_te = cne_rdtsc();
    m->tc                   = p->cbs;
    m->te                   = p->ebs;

    return 0;
}
