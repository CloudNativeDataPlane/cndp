/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef _CTHREAD_TLS_H_
#define _CTHREAD_TLS_H_

#include "cthread_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __APPLE__
#define CNE_PER_CTHREAD_SECTION_SIZE ((uintptr_t)&__stop_per_dt - (uintptr_t)&__start_per_dt)
#else
#define CNE_PER_CTHREAD_SECTION_SIZE 0
#endif

struct cthread_key {
    tls_destructor_func destructor;
};

struct cthread_tls {
    void *data[CTHREAD_MAX_KEYS];
    int nb_keys_inuse;
    struct cthread_sched *sched;
};

void _cthread_tls_destroy(struct cthread *ct);
void _cthread_key_pool_init(void);
int _cthread_tls_alloc(struct cthread *ct);

#ifdef __cplusplus
}
#endif

#endif /* _CTHREAD_TLS_H_ */
