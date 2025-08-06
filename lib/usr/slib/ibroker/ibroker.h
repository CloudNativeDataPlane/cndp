/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2025 Intel Corporation
 */

#ifndef _IBROKER_H_
#define _IBROKER_H_

/**
 * @file
 * CNE UIPI Broker or Interrupt Broker(ibroker)
 *
 * This library provides a simple interface to use UIPI features. The implementation will
 * abstract as much as possible to give the developer an opportunity to use UIPI features.
 *
 * Giving the developer an easy to use interface to the UIPI or interrupt based services.
 */

#include <cne_atomic.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IBROKER_API __attribute__((visibility("default")))

#define IBROKER_NAME_SIZE    64  /**< Max size of the broker instance name or service */
#define IBROKER_MAX_SERVICES 64  /**< Total number of services */
#define IBROKER_MAX_COUNT    128 /**< Max number of ibrokers allowed */

typedef int32_t broker_id_t;  /**< Broker ID */
typedef int32_t service_id_t; /**< Service ID */

/**
 * Function prototype for ibroker walk callback
 */
typedef int (*ibroker_walk_t)(broker_id_t bid, void *arg);

/**
 * Function prototype for service callback.
 */
typedef int (*ibroker_func_t)(int vector, void *arg);

struct service_info {
    char name[IBROKER_NAME_SIZE]; /**< Name of service */
    int valid;                    /**< Service is valid flag */
    int uintr_fd;                 /**< File descriptor */
    int16_t index;                /**< Index of the service */
    int16_t sid;                  /**< Server ID value */
    uint64_t call_cnt;            /**< Number of times the service was called */
    uint64_t err_cnt;             /**< Number of time an service error occurred */
};

typedef struct ibroker_info {
    char name[IBROKER_NAME_SIZE];                       /**< Name of this ibroker instance */
    int tid;                                            /**< Task ID value */
    broker_id_t bid;                                    /**< ibroker ID */
    uint64_t intrs;                                     /**< Interrupts statistice counter */
    uint64_t invalid_service;                           /**< Invalid service counter */
    struct service_info services[IBROKER_MAX_SERVICES]; /**< Array of all services possible */
} ibroker_info_t;

/**
 * Create a broker instance for the given name.
 *
 * @param name
 *   Name of the broker instance.
 * @return
 *   -1 if error or broker ID value.
 */
IBROKER_API broker_id_t ibroker_create(const char *name);

/**
 * Destroy a ibroker instance.
 *
 * This function uses the per thread ibroker value.
 *
 * @param bid
 *   The broker ID value to destroy
 */
IBROKER_API void ibroker_destroy(broker_id_t bid);

/**
 * Return the ibroker instance name.
 *
 * @param id
 *   The ibroker id to retrieve the name from, if -1 use current name.
 * @return
 *   Pointer to the name or NULL on error.
 */
IBROKER_API const char *ibroker_get_name(broker_id_t id);

/**
 * Add a service to a broker
 *
 * @param id
 *   The broker ID value
 * @param service
 *   The name of the service to add
 * @param vector
 *   The vector number to initialize
 * @param func
 *   The function to callback when the UIPI service is interrupted
 * @param arg
 *   The function callback argument from the caller.
 * @return
 *   service_id_t on success or -1 on error
 */
IBROKER_API service_id_t ibroker_add_service(broker_id_t id, const char *service, int vector,
                                             ibroker_func_t func, void *arg);

/**
 * Delete the given service in the broker defined by broker ID
 *
 * @param bid
 *   The broker ID to use for the delete operation
 * @param sid
 *   The service id to delete
 * @return
 *   0 on success or -1 on error
 */
IBROKER_API int ibroker_del_service(broker_id_t bid, service_id_t sid);

/**
 * Send a UIPI interrupt to the given broker and vector
 *
 * @param bid
 *   The broker ID to use for the senduipi() operation
 * @param sid
 *   The service ID to send the interrupt
 * @return
 *   0 on success or -1 on error
 */
IBROKER_API int ibroker_send(broker_id_t bid, service_id_t sid);

/**
 * Find the ibroker by name.
 *
 * @param name
 *   The ibroker name pointer
 * @return
 *   -1 if not found or broker ID value
 */
IBROKER_API broker_id_t ibroker_find(const char *name);

/**
 * Find a service in a given broker by name
 *
 * @param bid
 *   The broker ID to use for the senduipi() operation, if -1 then search all brokers.
 * @param name
 *   The service name to find in the given broker
 * @return
 *   -1 on error or the service ID value
 */
IBROKER_API service_id_t ibroker_find_service(broker_id_t bid, const char *name);

/**
 * Register sender with the given broker
 *
 * @param bid
 *   The broker ID to search
 * @param sid
 *   The vector ID value for the service
 * @return
 *   0 on success or -1 on error
 */
IBROKER_API int ibroker_register_sender(broker_id_t bid, service_id_t sid);

/**
 * Find a service FD in a broker with its service ID value
 *
 * @param bid
 *   The broker ID value
 * @param sid
 *   The server ID value to use for selecting the correct service
 * @return
 *   -1 on error or the server uintr_fd value
 */
IBROKER_API int ibroker_service_fd(broker_id_t bid, service_id_t sid);

/**
 * Return the service name given the broker and service ID
 *
 * @param bid
 *   The broker_id_t value
 * @param sid
 *   The service_id_t value
 * @return
 *   NULL on error or not found or it returns a pointer the service name
 */
IBROKER_API const char *ibroker_service_name(broker_id_t bid, service_id_t sid);

/**
 * Walk the list of ibroker instances and call a function with argument.
 *
 * @param func
 *   The ibroker_walk_t function pointer to call
 * @param arg
 *   The user defined pointer to be passed to the function.
 * @return
 *   0 on success or -1 on error
 */
IBROKER_API int ibroker_walk(ibroker_walk_t func, void *arg);

/**
 * Get a list of broker IDs
 *
 * @param ids
 *   Array to place the broker_id_t IDs, if NULL then return the number of brokers
 * @param len
 *   The length of the broker ids array, but be able to hold all broker ids or error is returned.
 * @return
 *   -1 on error or the number to broker IDs in the ids array.
 */
IBROKER_API int ibroker_id_list(broker_id_t *ids, int len);

/**
 * Return information about a broker
 *
 * @param bid
 *   The broker ID value
 * @param info
 *   The broker_info_t structure pointer.
 * @return
 *   0 on success or -1 on error.
 */
IBROKER_API int ibroker_info(broker_id_t bid, ibroker_info_t *info);

#ifdef __cplusplus
}
#endif

#endif /* _IBROKER_H_ */
