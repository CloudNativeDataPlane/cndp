/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018-2025 Cisco Systems, Inc.  All rights reserved.
 */

#ifndef _MEMIF_H_
#define _MEMIF_H_

#define CNE_MEMIF_COOKIE        0x3E31F20
#define CNE_MEMIF_VERSION_MAJOR 2
#define CNE_MEMIF_VERSION_MINOR 0
#define CNE_MEMIF_VERSION       ((CNE_MEMIF_VERSION_MAJOR << 8) | CNE_MEMIF_VERSION_MINOR)
#define CNE_MEMIF_NAME_SZ       32

/*
 * C2S: direction client -> server
 * S2C: direction server -> client
 */

/*
 *  Type definitions
 */

typedef enum cne_memif_msg_type {
    CNE_MEMIF_MSG_TYPE_NONE,
    CNE_MEMIF_MSG_TYPE_ACK,
    CNE_MEMIF_MSG_TYPE_HELLO,
    CNE_MEMIF_MSG_TYPE_INIT,
    CNE_MEMIF_MSG_TYPE_ADD_REGION,
    CNE_MEMIF_MSG_TYPE_ADD_RING,
    CNE_MEMIF_MSG_TYPE_CONNECT,
    CNE_MEMIF_MSG_TYPE_CONNECTED,
    CNE_MEMIF_MSG_TYPE_DISCONNECT,
} cne_memif_msg_type_t;

typedef enum {
    CNE_MEMIF_RING_C2S, /**< buffer ring in direction client -> server */
    CNE_MEMIF_RING_S2C, /**< buffer ring in direction server -> client */
} cne_memif_ring_type_t;

typedef enum {
    CNE_MEMIF_INTERFACE_MODE_ETHERNET,
    CNE_MEMIF_INTERFACE_MODE_IP,
    CNE_MEMIF_INTERFACE_MODE_PUNT_INJECT,
} cne_memif_interface_mode_t;

typedef uint16_t cne_memif_region_index_t;
typedef uint32_t cne_memif_region_offset_t;
typedef uint64_t cne_memif_region_size_t;
typedef uint16_t cne_memif_ring_index_t;
typedef uint32_t cne_memif_interface_id_t;
typedef uint16_t cne_memif_version_t;
typedef uint8_t cne_memif_log2_ring_size_t;

/*
 *  Socket messages
 */

/**
 * S2C
 * Contains server interfaces configuration.
 */
typedef struct __cne_packed {
    uint8_t name[CNE_MEMIF_NAME_SZ];               /**< Client app name */
    cne_memif_version_t min_version;               /**< lowest supported memif version */
    cne_memif_version_t max_version;               /**< highest supported memif version */
    cne_memif_region_index_t max_region;           /**< maximum num of regions */
    cne_memif_ring_index_t max_s2c_ring;           /**< maximum num of S2C ring */
    cne_memif_ring_index_t max_c2s_ring;           /**< maximum num of C2S rings */
    cne_memif_log2_ring_size_t max_log2_ring_size; /**< maximum ring size (as log2) */
} cne_memif_msg_hello_t;

/**
 * C2S
 * Contains information required to identify interface
 * to which the client wants to connect.
 */
typedef struct __cne_packed {
    cne_memif_version_t version;         /**< memif version */
    cne_memif_interface_id_t id;         /**< interface id */
    cne_memif_interface_mode_t mode : 8; /**< interface mode */
    uint8_t secret[24];                  /**< optional security parameter */
    uint8_t name[CNE_MEMIF_NAME_SZ];     /**< Client app name */
} cne_memif_msg_init_t;

/**
 * C2S
 * Request server to add new shared memory region to server interface.
 * Shared files file descriptor is passed in cmsghdr.
 */
typedef struct __cne_packed {
    cne_memif_region_index_t index; /**< shm regions index */
    cne_memif_region_size_t size;   /**< shm region size */
} cne_memif_msg_add_region_t;

/**
 * C2S
 * Request server to add new ring to server interface.
 */
typedef struct __cne_packed {
    uint16_t flags;                            /**< flags */
#define CNE_MEMIF_MSG_ADD_RING_FLAG_C2S 1      /**< ring is in C2S direction */
    cne_memif_ring_index_t index;              /**< ring index */
    cne_memif_region_index_t region;           /**< region index on which this ring is located */
    cne_memif_region_offset_t offset;          /**< buffer start offset */
    cne_memif_log2_ring_size_t log2_ring_size; /**< ring size (log2) */
    uint16_t private_hdr_size;                 /**< used for private metadata */
} cne_memif_msg_add_ring_t;

/**
 * C2S
 * Finalize connection establishment.
 */
typedef struct __cne_packed {
    uint8_t if_name[CNE_MEMIF_NAME_SZ]; /**< client interface name */
} cne_memif_msg_connect_t;

/**
 * S2C
 * Finalize connection establishment.
 */
typedef struct __cne_packed {
    uint8_t if_name[CNE_MEMIF_NAME_SZ]; /**< server interface name */
} cne_memif_msg_connected_t;

/**
 * C2S & S2C
 * Disconnect interfaces.
 */
typedef struct __cne_packed {
    uint32_t code;      /**< error code */
    uint8_t string[96]; /**< disconnect reason */
} cne_memif_msg_disconnect_t;

typedef struct __cne_packed __cne_aligned(128)
{
    cne_memif_msg_type_t type : 16;
    union {
        cne_memif_msg_hello_t hello;
        cne_memif_msg_init_t init;
        cne_memif_msg_add_region_t add_region;
        cne_memif_msg_add_ring_t add_ring;
        cne_memif_msg_connect_t connect;
        cne_memif_msg_connected_t connected;
        cne_memif_msg_disconnect_t disconnect;
    };
}
cne_memif_msg_t;

/*
 *  Ring and Descriptor Layout
 */

/**
 * Buffer descriptor.
 */
typedef struct __cne_packed {
    uint16_t flags;                   /**< flags */
#define CNE_MEMIF_DESC_FLAG_NEXT 1    /**< is chained buffer */
    cne_memif_region_index_t region;  /**< region index on which the buffer is located */
    uint32_t length;                  /**< buffer length */
    cne_memif_region_offset_t offset; /**< buffer offset */
    uint32_t metadata;
} cne_memif_desc_t;

#define CNE_MEMIF_CACHELINE_ALIGN_MARK(mark) CNE_MARKER mark __cne_cache_aligned;

typedef struct {
    CNE_MEMIF_CACHELINE_ALIGN_MARK(cacheline0);
    uint32_t cookie;                   /**< MEMIF_COOKIE */
    uint16_t flags;                    /**< flags */
#define CNE_MEMIF_RING_FLAG_MASK_INT 1 /**< disable interrupt mode */
    uint16_t head;                     /**< pointer to ring buffer head */
    CNE_MEMIF_CACHELINE_ALIGN_MARK(cacheline1);
    uint16_t tail; /**< pointer to ring buffer tail */
    CNE_MEMIF_CACHELINE_ALIGN_MARK(cacheline2);
    cne_memif_desc_t desc[0]; /**< buffer descriptors */
} cne_memif_ring_t;

#endif /* _MEMIF_H_ */
