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
    int (*setfunc)(struct chnl *ch, int, int, const void *, uint32_t);
    int (*getfunc)(struct chnl *ch, int, int, void *, uint32_t *);
};

/**
 * @internal
 * @brief Add a protosw structure to the internal list.
 *
 * @param ps
 *   The protosw structure to add
 * @return
 *   0 on success or -1 on failure
 */
int cnet_chnl_opt_add(struct chnl_optsw *ps);

/**
 * @internal
 * @brief Iterate over the list of protosw structures for a given channel to set.
 *
 * @param ch
 *   The pointer to the channel structure
 * @param level
 *   The level at which to search
 * @param optname
 *   The option name to match
 * @param optval
 *   The option value to be set
 * @param optlen
 *   The length of options value.
 * @return
 *   0 on success or -1 on error
 */
int cnet_chnl_opt_iterate_set(struct chnl *ch, int level, int optname, const void *optval,
                              uint32_t optlen);

/**
 * @internal
 * @brief Iterate over the list of protosw structures for a given channel to get.
 *
 * @param ch
 *   The pointer to the channel structure
 * @param level
 *   The level at which to search
 * @param optname
 *   The option name to match
 * @param optval
 *   The option value to be get
 * @param optlen
 *   The length of options value.
 * @return
 *   0 on success or -1 on error
 */
int cnet_chnl_opt_iterate_get(struct chnl *ch, int level, int optname, void *optval,
                              uint32_t *optlen);

/**
 * @internal
 * @brief Get a option value
 *
 * @param optval
 *   The option value to place the value
 * @param optlen
 *   The size of the option value
 * @return
 *   The value returned into the option value buffer.
 */
uint32_t chnl_optval_get(const void *optval, uint32_t optlen);

/**
 * @brief Set a channel option
 *
 * @param cd
 *   The channel descriptor to use for the set
 * @param level
 *   The level of the option to set
 * @param optname
 *   The name of the option to set
 * @param optval
 *   The option value to set
 * @param optlen
 *   The option length for the set
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int chnl_set_opt(int cd, int level, int optname, const void *optval, int optlen);

/**
 * @brief Get a channel option
 *
 * @param cd
 *   The channel descriptor to use for the get
 * @param level
 *   The level of the option to get
 * @param optname
 *   The name of the option to get
 * @param optval
 *   The option value to get
 * @param optlen
 *   The option length for the get
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int chnl_get_opt(int cd, int level, int optname, void *optval, socklen_t *optlen);

#ifdef __cplusplus
}
#endif

#endif /* __CNET_CHNL_OPT */
