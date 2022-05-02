/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2016-2022 Intel Corporation
 */

#ifndef __CNET_CHNL_OPT
#define __CNET_CHNL_OPT

/**
 * @file
 * CNET Channel option routines and constants.
 */

#include <stdint.h>            // for uint32_t, int32_t
#include <sys/socket.h>        // for socklen_t

struct chnl;
#ifdef __cplusplus
extern "C" {
#endif

/*
 * chnl_optsw - channel option switch structure
 */
struct chnl_optsw {
    int32_t level;
    int (*setfunc)(struct chnl *, int, int, const void *, uint32_t);
    int (*getfunc)(struct chnl *, int, int, void *, uint32_t *);
};

CNDP_API int cnet_chnl_opt_add(struct chnl_optsw *);
CNDP_API int cnet_chnl_opt_iterate_set(struct chnl *ch, int level, int optname, const void *optval,
                                       uint32_t optlen);
CNDP_API int cnet_chnl_opt_iterate_get(struct chnl *, int level, int optname, void *optval,
                                       uint32_t *optlen);

CNDP_API int chnl_set_opt(struct chnl *ch, int level, int optname, const void *optval, int optlen);
CNDP_API int chnl_get_opt(struct chnl *ch, int level, int optname, void *optval, socklen_t *optlen);
CNDP_API uint32_t chnl_optval_get(const void *optval, uint32_t optlen);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_CHNL_OPT */
