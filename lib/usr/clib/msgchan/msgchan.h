/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation.
 */

#ifndef _MSGCHAN_H_
#define _MSGCHAN_H_

#include <sys/queue.h>
#include <cne_common.h>
#include <cne_ring.h>
#include <cne_ring_api.h>

/**
 * @file
 * Message Channels
 *
 * Create a message channel using two lockless rings to communicate between two threads.
 *
 * Message channels are similar to pipes in Linux and other platforms, but does not support
 * message passing between processes.
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#define MC_NAME_SIZE (CNE_NAME_LEN + 4) /**< Max size of the msgchan name */
#define MC_RECV_RING 0                  /**< Receive index into msgchan_t.rings */
#define MC_SEND_RING 1                  /**< Send index into msgchan_t.rings */

#define MC_NO_CHILD_CREATE \
    0x80000000 /**< If set in mc_create() flags then child will not be created */

typedef void msgchan_t; /**< Opaque msgchan structure pointer */

typedef struct msgchan_info {
    cne_ring_t *recv_ring;  /**< Pointers to the recv ring */
    cne_ring_t *send_ring;  /**< Pointers to the send ring */
    int child_count;        /**< Number of children */
    uint64_t send_calls;    /**< Number of send calls */
    uint64_t send_cnt;      /**< Number of objects sent */
    uint64_t recv_calls;    /**< Number of receive calls */
    uint64_t recv_cnt;      /**< Number of objects received */
    uint64_t recv_timeouts; /**< Number of receive timeouts */
} msgchan_info_t;

/**
 * @brief Create a message channel
 *
 * Calling mc_create() with an existing channel name will create a child
 * channel attached to the parent channel.
 *
 * @param name
 *   The name of the message channel
 * @param sz
 *   The number of entries in the lockless ring for each direction.
 * @param flags
 *   The cne_ring_t flags for SP/SC or MP/MC type flags, look at cne_ring_create()
 *   Defaults to (RING_F_MP_ENQ | RING_F_MC_DEQ) if flags is zero. Use the flags
 *   (RING_F_SP_ENQ | RING_F_SC_DEQ);
 *   Or in the bit MC_NO_CHILD_CREATE to not allow creating a child, NULL will be returned.
 * @return
 *   The pointer to the msgchan structure or NULL on error
 */
CNDP_API msgchan_t *mc_create(const char *name, int sz, uint32_t flags);

/**
 * @brief Destroy the message channel and free resources.
 *
 * @param mc
 *   The msgchan structure pointer to destroy
 * @return
 *   N/A
 */
CNDP_API void mc_destroy(msgchan_t *mc);

/**
 * @brief Send object messages to the other end of the channel
 *
 * @param mc
 *   The message channel structure pointer
 * @param objs
 *   An array of void *objects to send
 * @param count
 *   The number of entries in the objs array.
 * @return
 *   -1 on error or number of objects sent.
 */
CNDP_API int mc_send(msgchan_t *mc, void **objs, int count);

/**
 * @brief Receive message routine from other end of the channel
 *
 * @param mc
 *   The message channel structure pointer
 * @param objs
 *   An array of objects pointers to place the received objects pointers
 * @param count
 *   The number of entries in the objs array.
 * @param msec
 *   Number of milliseconds to wait for data, if return without waiting.
 * @return
 *   -1 on error or number of objects
 */
CNDP_API int mc_recv(msgchan_t *mc, void **objs, int count, uint64_t msec);

/**
 * @brief Lookup a message channel by name - parent only lookup
 *
 * @param name
 *   The name of the message channel to find, which is for parent channels
 * @return
 *   NULL if not found, otherwise the message channel pointer
 */
CNDP_API msgchan_t *mc_lookup(const char *name);

/**
 * @brief Return the name string for the msgchan_t pointer
 *
 * @param mc
 *   The message channel structure pointer
 * @return
 *   NULL if invalid pointer or string to message channel name
 */
CNDP_API const char *mc_name(msgchan_t *mc);

/**
 * @brief Return size and free space in the Producer/Consumer rings.
 *
 * @param mc
 *   The message channel structure pointer
 * @param recv_free_cnt
 *   The pointer to place the receive free count, can be NULL.
 * @param send_free_cnt
 *   The pointer to place the send free count, can be NULL.
 * @return
 *   -1 on error or size of the massage channel rings.
 */
CNDP_API int mc_size(msgchan_t *mc, int *recv_free_cnt, int *send_free_cnt);

/**
 * Return the message channel information structure data
 *
 * @param _mc
 *   The message channel structure pointer
 * @param info
 *   The pointer to the msgchan_info_t structure
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int mc_info(msgchan_t *_mc, msgchan_info_t *info);

/**
 * @brief Dump out the details of the given message channel structure
 *
 * @param mc
 *   The message channel structure pointer
 * @return
 *   -1 if mc is NULL or 0 on success
 */
CNDP_API void mc_dump(msgchan_t *mc);

/**
 * @brief List out all message channels currently created.
 */
CNDP_API void mc_list(void);

#ifdef __cplusplus
}
#endif

#endif /* _MSGCHAN_H_ */
