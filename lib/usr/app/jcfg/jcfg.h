/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) <2019-2020>, Intel Corporation. All rights reserved.
 */

#ifndef _JCFG_H_
#define _JCFG_H_

/**
 * @file
 * JSON configuration using json-c
 */

#include <pthread.h>           // for pthread_t
#include <sched.h>             // for cpu_set_t
#include <stdint.h>            // for uint16_t, uint32_t, uint64_t, int64_t
#include <sys/socket.h>        // for accept, bind, listen, socket, AF_UNIX
#include <sys/queue.h>         // for STAILQ_ENTRY, STAILQ_HEAD
#include <sys/un.h>            // for sockaddr_un
#include <bsd/sys/bitstring.h>
#include <json-c/json_object.h>
#include <json-c/json_tokener.h>
#include <json-c/json_util.h>
#include <json-c/json_visit.h>        // for json_c_visit_userfunc
#include <json-c/linkhash.h>
#include <cne_common.h>        // for CNDP_API, CNE_STD_C11
#include <cne_log.h>
#include <cne_mmap.h>        // for mmap_t
#include <cne_thread.h>
#include <pktmbuf.h>        // for pktmbuf_info_t

#define DEFAULT_CHUNK_SIZE   1024
#define UMEM_MAX_REGIONS     128
#define JCFG_MAX_STRING_SIZE 32

#ifdef __cplusplus
extern "C" {
#endif

struct json_object;

/**
 * The standard list of section names used in  JCFG json-c files.
 */
#define APP_TAG         "application"
#define DEFAULT_TAG     "defaults"
#define OPTION_TAG      "options"
#define UMEM_TAG        "umems"
#define LPORT_TAG       "lports"
#define LGROUP_TAG      "lcore-groups"
#define THREAD_TAG      "threads"
#define LPORT_GROUP_TAG "lport-groups"
#define USER_TAG        "users"

/**
 * Macro to initialize a const char *tags[] type array for indexing with jcfg_tag_t.
 *
 * @note: make sure this matches the jcfg_cb_type_t enum order.
 */
#define JCFG_TAG_NAMES                                                                 \
    {                                                                                  \
        APP_TAG, DEFAULT_TAG, OPTION_TAG, UMEM_TAG, LPORT_TAG, LGROUP_TAG, THREAD_TAG, \
            LPORT_GROUP_TAG, USER_TAG,                                                 \
    }

/**
 * Enumeration of jcfg process callback types
 */
typedef enum {
    /* jcfg_opt_t types */
    JCFG_APPLICATION_TYPE, /**< Application Callback flag */
    JCFG_DEFAULT_TYPE,     /**< Default option Callback flag */
    JCFG_OPTION_TYPE,      /**< Options Callback flag */
    /* Non jcfg_opt_t types */
    JCFG_UMEM_TYPE,        /**< UMEM Callback flag */
    JCFG_LPORT_TYPE,       /**< LPORT Callback flag */
    JCFG_LGROUP_TYPE,      /**< LGROUP Callback flag */
    JCFG_THREAD_TYPE,      /**< Thread Callback flag */
    JCFG_LPORT_GROUP_TYPE, /**< LPORT GROUP Callback flag */
    JCFG_USER_TYPE,        /**< User Callback flag */

    JCFG_MAX_TYPES /**< Maximum tag types */
} jcfg_cb_type_t;

/**
 * Known types of objects we can have in a JSON file for JCFG.
 */
typedef enum {
    UNKNOWN_OPT_TYPE,
    BOOLEAN_OPT_TYPE,
    STRING_OPT_TYPE,
    INTEGER_OPT_TYPE,
    ARRAY_OPT_TYPE,
    OBJECT_OPT_TYPE
} obj_type_t;

/**
 * JCFG Object information
 */
typedef struct obj_value {
    obj_type_t type;    /**< Object type */
    uint16_t array_sz;  /**< Array size if array type */
    uint16_t reserved;  /* reserved space */
    CNE_STD_C11 union { /* Use union members directly */
        int boolean;    /**< Boolean option */
        int64_t value;  /**< Value of option if integer */
        char *str;      /**< String pointer if string (must be freed) */
        struct obj_value **arr;
    };
} obj_value_t;

/**
 * Common Header for all JCFG objects or groups
 */
#define JCFG_COMMON_HDR(_t)                                         \
    STAILQ_ENTRY(_t) next; /**< Pointer to next object structure */ \
    char *name;            /**< Name of the object */               \
    char *desc;            /**< The description of the object */    \
    void *priv_;           /**< User private data pointer */        \
    jcfg_cb_type_t cbtype  /**< The object callback type */

/**
 * A template structure to be used as a generic overlay to the jcfg objects.
 */
typedef struct jcfg_hdr {
    JCFG_COMMON_HDR(jcfg_hdr); /**< Common header for all jcfg objects */
} jcfg_hdr_t;

/**
 * JCFG option structure
 */
typedef struct jcfg_opt {
    JCFG_COMMON_HDR(jcfg_opt); /**< Common header for all jcfg objects */
    obj_value_t val;           /**< Object value */
} jcfg_opt_t;

typedef struct region_info {
    char *addr;           /**< Address of the buffer pool in UMEM space */
    pktmbuf_info_t *pool; /**< pktmbuf_info_t pool pointer */
    uint32_t bufcnt;      /**< Size of each region in 1K bufcnt increments */
} region_info_t;

/**
 * UMEM information for JCFG
 */
typedef struct jcfg_umem {
    JCFG_COMMON_HDR(jcfg_umem); /**< Common header for all jcfg objects */
    mmap_t *mm;                 /**< mmap_t pointer for umem area */
    uint32_t bufcnt;            /**< Number of objects to create */
    uint32_t bufsz;             /**< Size of each object buffer */
    uint16_t mtype;             /**< MMAP memory type to allocate */
    uint16_t rxdesc;            /**< Number of Rx descriptors */
    uint16_t txdesc;            /**< Number of Tx descriptors */
    uint16_t idx;               /**< The UMEM index id 0 to N */
    uint16_t shared_umem;       /**< Enable shared umem support */
    uint16_t region_cnt;        /**< Number of regions defined */
    region_info_t *rinfo;       /**< Region information data */
} jcfg_umem_t;

/**
 * JCFG lport information
 */
typedef struct jcfg_lport {
    JCFG_COMMON_HDR(jcfg_lport); /**< Common header for all jcfg objects */
    char *netdev;                /**< The netdev name */
    char *pmd_name;              /**< The PMD name */
    char *pmd_opts;              /**< The PMD opts string */
    char *umem_name;             /**< UMEM assigned to this lport to use */
    jcfg_umem_t *umem;           /**< UMEM configuration structure */
    uint16_t region_idx;         /**< UMEM region index */
    uint16_t lpid;               /**< The lport index number */
    uint16_t qid;                /**< The queue ID number */
    uint16_t busy_timeout;       /**< busy timeout value in milliseconds */
    uint16_t busy_budget;        /**< busy budget 0xFFFF disabled, 0 use default, >0 budget */
    uint16_t flags; /**< Flags to configure lport in lport_cfg_t.flags in cne_lport.h */
} jcfg_lport_t;

/** JCFG lport configuration names */
#define JCFG_LPORT_PMD_NAME          "pmd"
#define JCFG_LPORT_UMEM_NAME         "umem"
#define JCFG_LPORT_REGION_NAME       "region"
#define JCFG_LPORT_QID_NAME          "qid"
#define JCFG_LPORT_DESCRIPTION_NAME  "description"
#define JCFG_LPORT_DESC_NAME         "desc"
#define JCFG_LPORT_BUSY_POLL_NAME    "busy_poll"
#define JCFG_LPORT_BUSY_POLLING_NAME "busy_polling"
#define JCFG_LPORT_BUSY_TIMEOUT_NAME "busy_timeout"
#define JCFG_LPORT_BUSY_BUDGET_NAME  "busy_budget"
#define JCFG_LPORT_UNPRIVILEGED_NAME "unprivileged"
#define JCFG_LPORT_FORCE_WAKEUP_NAME "force_wakeup"
#define JCFG_LPORT_SKB_MODE_NAME     "skb_mode"

/**
 * JCFG  lgroup for lcore allocations
 */
typedef struct jcfg_lgroup {
    JCFG_COMMON_HDR(jcfg_lgroup); /**< Common header for all jcfg objects */
    uint16_t lcore_cnt;           /**< Number of lcores in the array entry */
    cpu_set_t lcore_bitmap;       /**< Bitmap of lcores used for affinity */
} jcfg_lgroup_t;

/**
 * JCFG Thread information
 */
typedef struct jcfg_thd {
    JCFG_COMMON_HDR(jcfg_thd); /**< Common header for all jcfg objects */
    char *group_name;          /**< lcore group name */
    char *thread_type;         /**< User supplied thread type */
    jcfg_lgroup_t *group;      /**< Pointer to lcore group */
    uint16_t lport_cnt;        /**< Number of lports */
    uint16_t lport_sz;         /**< Size of lport arrays */
    uint16_t idx;              /**< Thread index value */
    char **lport_names;        /**< List of lport names */
    jcfg_lport_t **lports;     /**< The lports attached to this configuration */
    int tid;                   /**< System Thread id value */
    volatile uint16_t quit;    /**< Set to non-zero to force thread to quit */
    volatile uint16_t pause;   /**< Set to non-zero to pause thread */
} jcfg_thd_t;

/**
 * JCFG lport group information
 */
typedef struct jcfg_lport_group {
    JCFG_COMMON_HDR(jcfg_lport_group); /**< Common header for all jcfg objects */
    char **netdev_names;               /**< List of netdev names */
    int num_netdev_names;              /**< Number of netdev names */
    char **thread_names;               /**< List of thread names */
    int num_thread_names;              /**< Number of thread names */
    void *qlist;                       /**< List of queue ids */
    uint16_t *max_q;                   /**< maximum queues for each netdev */
    uint16_t total_q;                  /**< total queues from all netdevs */
    char *pmd_name;                    /**< The PMD name */
    char *pmd_opts;                    /**< The PMD opts string */
    char *umem_name;                   /**< UMEM assigned to this lport group */
    jcfg_umem_t *umem;                 /**< UMEM configuration structure */
    uint16_t busy_timeout;             /**< busy timeout value in milliseconds */
    uint16_t busy_budget;              /**< busy budget 0xFFFF disabled, 0 use default, >0 budget */
    uint16_t flags; /**< Flags to configure lport in lport_cfg_t.flags in cne_lport.h */
} jcfg_lport_group_t;

/** JCFG lport group configuration names */
#define JCFG_LPORT_GROUP_NETDEV_NAMES_NAME "netdevs"
#define JCFG_LPORT_GROUP_QUEUES_NAME       "queues"
#define JCFG_LPORT_GROUP_THREAD_NAMES_NAME "threads"

/**
 *  A user defined object type
 */
typedef struct jcfg_user {
    JCFG_COMMON_HDR(jcfg_user); /**< Common header for all jcfg objects */
    obj_value_t val;            /**< Object value */
} jcfg_user_t;

/**
 * Simple structure to hold an array of object in a list.
 *
 * The list array uses realloc() to grow the list.
 */
typedef struct jcfg_list {
    int cnt;     /**< Number of entries in the list */
    int sz;      /**< Total number of available entries in list */
    void **list; /**< Object pointers for the list */
} jcfg_list_t;

/**
 * Main structure to hold all of the jcfg configuration information
 */
typedef struct jcfg_data {
    STAILQ_HEAD(, jcfg_opt) application; /**< Application configuration */
    STAILQ_HEAD(, jcfg_opt) defaults;    /**< config default values */
    STAILQ_HEAD(, jcfg_opt) options;     /**< Application options */
    STAILQ_HEAD(, jcfg_umem) umems;      /**< UMEM configurations */
    STAILQ_HEAD(, jcfg_lport) lports;    /**< lport configurations */
    STAILQ_HEAD(, jcfg_lgroup) lgroups;  /**< lcore groups for threads */
    STAILQ_HEAD(, jcfg_thd) threads;     /**< Defined set of threads */
    /** Defined set of lport_groups */
    STAILQ_HEAD(, jcfg_lport_group) lport_groups;
    STAILQ_HEAD(, jcfg_user) users; /**< User defined values */
    jcfg_list_t lport_list;         /**< List of lport objects for easy indexing */
    jcfg_list_t umem_list;          /**< List of umem objects for easy indexing */
    jcfg_list_t thd_list;           /**< List of thread objects for easy indexing */
    int thread_count;               /**< Number of threads defined objects */
    int lport_count;                /**< Number of lports defined objects */
    int umem_count;                 /**< Number of umems defined objects */
    int app_count;                  /**< Number of applications defined objects */
    int default_count;              /**< Number of defaults defined objects */
    int opt_count;                  /**< Number of options defined objects */
    int lgroup_count;               /**< Number of lgroups defined objects */
    int lport_group_count;          /**< Number of lport groups defined objects */
    int user_count;                 /**< Number of user defined objects */
} jcfg_data_t;

/**
 * A union of the different objects in JSON configuration file.
 */
typedef union {
    jcfg_hdr_t *hdr;         /**< Template header for a generic object pointer */
    jcfg_opt_t *app;         /**< Application type object pointer */
    jcfg_opt_t *def;         /**< Define type object pointer */
    jcfg_opt_t *opt;         /**< Option type object pointer */
    jcfg_umem_t *umem;       /**< UMEM type object pointer */
    jcfg_lport_t *lport;     /**< lport type object pointer */
    jcfg_lgroup_t *lgroup;   /**< lgroup type object pointer */
    jcfg_thd_t *thd;         /**< Thread type object pointer */
    jcfg_lport_group_t *lpg; /**< lport group type object pointer */
    jcfg_user_t *usr;        /**< User defined object pointer */
} jcfg_obj_t;

struct jcfg_info_s;

/**
 * JCFG Parser callback function prototype. Called once for each parsed object in the JSON file.
 *
 * @param jinfo
 *   The jcfg information structure pointer
 * @param obj
 *   The object (application, thread, lport, ...) pointer
 * @param arg
 *   The argument for the callback passed in by the user.
 * @param idx
 *   The index pointer in the JSON configuration relative to the group being parsed.
 * @return
 *   0 on success or -1 on error
 */
typedef int jcfg_parse_cb_t(struct jcfg_info_s *jinfo, void *obj, void *arg, int idx);

/**
 * The JCFG basic information structure
 */
typedef struct jcfg_info_s {
    uint32_t flags;         /**< Flags used in JCFG parsing of file. */
    int listen_sock;        /**< Socket file descriptor */
    struct sockaddr_un sun; /**< The path to the local domain socket */
    volatile int running;   /**< The running flag for the socket listener */
    void *cfg;              /**< The internal JCFG configuration data structure pointer */
    jcfg_parse_cb_t *cb;    /**< The callback function for parsing JSON file */
} jcfg_info_t;

/**
 * Flags used for jcfg_info_t.flags value
 */
enum {
    JCFG_NO_FLAGS         = 0,
    JCFG_INFO_VERBOSE     = (1 << 0), /**< Enable VERBOSE printout after parsing json data */
    JCFG_DEBUG_DECODING   = (1 << 1), /**< Debug the JCGF decoding of json text */
    JCFG_DEBUG_PARSING    = (1 << 2), /**< Debug the JCGF parsing of json text */
    JCFG_INFO_STRICT_FLAG = (1 << 3), /**< Force strict JSON parsing, no JSON-C support */
    JCFG_PARSE_FILE       = (1 << 4), /**< Get JSON text from a file */
    JCFG_PARSE_SOCKET     = (1 << 5), /**< Get the JSON text from a socket or local domain socket */
    JCFG_PARSE_STRING     = (1 << 6), /**< Use the string as the JSON text data */
};

/**
 * Object callback functions
 *
 * @param jinfo
 *   The jcfg information structure pointer
 * @param obj
 *   The object (application, thread, lport, ...) pointer
 * @param arg
 *   The argument for the callback passed in by the user.
 * @param idx
 *   The index pointer in the JSON configuration relative to the group being parsed.
 * @return
 *   0 on success or -1 on error
 */
typedef int jcfg_cb_t(jcfg_info_t *jinfo, void *obj, void *arg, int idx);

/**
 * Foreach routines for each object type.
 *
 * @param jinfo
 *   The jcfg information structure pointer
 * @param cbtype
 *   The jcfg_cb_type_t enum value.
 * @param func
 *   The function to callback for each object.
 * @param arg
 *   The user supplied argument passed to the *func* function
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int jcfg_object_foreach(jcfg_info_t *jinfo, jcfg_cb_type_t cbtype, jcfg_cb_t *func,
                                 void *arg);

/**
 * Helper macros for each type of object to iterate over.
 */
#define jcfg_application_foreach(j, f, a) jcfg_object_foreach(j, JCFG_APPLICATION_TYPE, f, a)
#define jcfg_defaults_foreach(j, f, a)    jcfg_object_foreach(j, JCFG_DEFAULT_TYPE, f, a)
#define jcfg_option_foreach(j, f, a)      jcfg_object_foreach(j, JCFG_OPTION_TYPE, f, a)
#define jcfg_umem_foreach(j, f, a)        jcfg_object_foreach(j, JCFG_UMEM_TYPE, f, a)
#define jcfg_lport_foreach(j, f, a)       jcfg_object_foreach(j, JCFG_LPORT_TYPE, f, a)
#define jcfg_lgroup_foreach(j, f, a)      jcfg_object_foreach(j, JCFG_LGROUP_TYPE, f, a)
#define jcfg_thread_foreach(j, f, a)      jcfg_object_foreach(j, JCFG_THREAD_TYPE, f, a)
#define jcfg_lport_group_foreach(j, f, a) jcfg_object_foreach(j, JCFG_LPORT_GROUP_TYPE, f, a)
#define jcfg_user_foreach(j, f, a)        jcfg_object_foreach(j, JCFG_USER_TYPE, f, a)

/**
 * Object section lookup by name routines.
 *
 * @param jinfo
 *   The jcfg information structure pointer
 * @param cbtype
 *   The JCFG Tag Type enum value
 * @param name
 *   The name string for the object in the JSON group being searched.
 * @return
 *   The object pointer or NULL if not found or error
 */
CNDP_API void *jcfg_object_lookup(jcfg_info_t *jinfo, jcfg_cb_type_t cbtype, const char *name);

#define jcfg_lookup_option(j, n)      (jcfg_opt_t *)jcfg_object_lookup(j, JCFG_OPTION_TYPE, n)
#define jcfg_lookup_default(j, n)     (jcfg_opt_t *)jcfg_object_lookup(j, JCFG_DEFAULT_TYPE, n)
#define jcfg_lookup_application(j, n) (jcfg_opt_t *)jcfg_object_lookup(j, JCFG_APPLICATION_TYPE, n)
#define jcfg_lookup_umem(j, n)        (jcfg_umem_t *)jcfg_object_lookup(j, JCFG_UMEM_TYPE, n)
#define jcfg_lookup_lport(j, n)       (jcfg_lport_t *)jcfg_object_lookup(j, JCFG_LPORT_TYPE, n)
#define jcfg_lookup_lport(j, n)       (jcfg_lport_t *)jcfg_object_lookup(j, JCFG_LPORT_TYPE, n)
#define jcfg_lookup_lgroup(j, n)      (jcfg_lgroup_t *)jcfg_object_lookup(j, JCFG_LGROUP_TYPE, n)
#define jcfg_lookup_thread(j, n)      (jcfg_thd_t *)jcfg_object_lookup(j, JCFG_THREAD_TYPE, n)
#define jcfg_lookup_lport_group(j, n) \
    (jcfg_lport_group_t *)jcfg_object_lookup(j, JCFG_LPORT_GROUP_TYPE, n)
#define jcfg_lookup_user(j, n) (jcfg_user_t *)jcfg_object_lookup(j, JCFG_USER_TYPE, n)

/**
 * Count the number of objects in a given group or type (lport, thread, ...)
 *
 * @param jinfo
 *   The jcfg information structure pointer
 * @param cbtype
 *   The type of the object to count
 * @return
 *   The number of object in the given type.
 */
CNDP_API int jcfg_num_objects(jcfg_info_t *jinfo, jcfg_cb_type_t cbtype);

/**
 * Helper macros for getting the number of object in a section
 */
#define jcfg_num_applications(j) jcfg_num_objects(j, JCFG_APPLICATION_TYPE)
#define jcfg_num_defaults(j)     jcfg_num_objects(j, JCFG_DEFAULT_TYPE)
#define jcfg_num_options(j)      jcfg_num_objects(j, JCFG_OPTION_TYPE)
#define jcfg_num_lports(j)       jcfg_num_objects(j, JCFG_LPORT_TYPE)
#define jcfg_num_lgroups(j)      jcfg_num_objects(j, JCFG_LGROUP_TYPE)
#define jcfg_num_threads(j)      jcfg_num_objects(j, JCFG_THREAD_TYPE)
#define jcfg_num_lport_groups(j) jcfg_num_objects(j, JCFG_LPORT_GROUP_TYPE)
#define jcfg_num_umems(j)        jcfg_num_objects(j, JCFG_UMEM_TYPE)

/**
 * Get the value of the defaults section given of the same name
 *
 * @param jinfo
 *   The jcfg information structure pointer
 * @param name
 *   The string name of the object to search for in the default list.
 * @param val
 *   Location to place the found object data.
 * @return
 *   obj_type_t (boolean, string or int) on success and *val* is valid or -1 on error
 */
CNDP_API int jcfg_default_get(jcfg_info_t *jinfo, const char *name, uint64_t *val);

/**
 * Get the array of the defaults section given of the same name
 *
 * @param jinfo
 *   The jcfg information structure pointer
 * @param name
 *   The string name of the array to search for in the default list.
 * @param val_arr
 *   Location to place the found object data array.
 * @return
 *   0 on success and *val_arr* is valid or -1 on error
 */
CNDP_API int jcfg_default_array_get(jcfg_info_t *jinfo, const char *name, obj_value_t **val_arr);

/**
 * Get the value of the default section given of the same name for a boolean value
 *
 * @param jinfo
 *   The jcfg information structure pointer
 * @param name
 *   The string name of the object to search for in the default list.
 * @param v
 *   Location to place the found object data.
 * @return
 *   0 on success and *val* is valid or -1 on error
 */
static inline int
jcfg_default_get_bool(jcfg_info_t *jinfo, const char *name, uint32_t *v)
{
    uint64_t val;

    if (jcfg_default_get(jinfo, name, &val) < 0)
        return -1;
    *v = (uint32_t)val;
    return 0;
}

/**
 * Get the value of the default section given of the same name for a u32 bit value
 *
 * @param jinfo
 *   The jcfg information structure pointer
 * @param name
 *   The string name of the object to search for in the default list.
 * @param v
 *   Location to place the found object data.
 * @return
 *   0 on success and *val* is valid or -1 on error
 */
static inline int
jcfg_default_get_u32(jcfg_info_t *jinfo, const char *name, uint32_t *v)
{
    uint64_t val;

    if (jcfg_default_get(jinfo, name, &val) < 0)
        return -1;
    *v = (uint32_t)val;
    return 0;
}

/**
 * Get the value of the default section given the name for a u16 bit value
 *
 * @param jinfo
 *   The jcfg information structure pointer
 * @param name
 *   The string name of the object to search for in the default list.
 * @param v
 *   Location to place the found object data.
 * @return
 *   0 on success and *val* is valid or -1 on error
 */
static inline int
jcfg_default_get_u16(jcfg_info_t *jinfo, const char *name, uint16_t *v)
{
    uint64_t val;

    if (jcfg_default_get(jinfo, name, &val) < 0)
        return -1;
    *v = (uint16_t)val;
    return 0;
}

/**
 * Get the value of the default section given of the same name for a string value
 *
 * @param jinfo
 *   The jcfg information structure pointer
 * @param name
 *   The string name of the object to search for in the default list.
 * @param v
 *   Location to place the found object data.
 * @return
 *   0 on success and *val* is valid or -1 on error
 */
static inline int
jcfg_default_get_string(jcfg_info_t *jinfo, const char *name, char **v)
{
    uint64_t val;

    if (jcfg_default_get(jinfo, name, &val) < 0)
        return -1;
    *v = (char *)val;
    return 0;
}

/**
 * Get the value of the options section given of the same name
 *
 * @param jinfo
 *   The jcfg information structure pointer
 * @param name
 *   The string name of the object to search for in the default list.
 * @param val
 *   Location to place the found object data.
 * @return
 *   obj_type_t (boolean, string or int) on success and *val* is valid or -1 on error
 */
CNDP_API int jcfg_option_get(jcfg_info_t *jinfo, const char *name, uint64_t *val);

/**
 * Get the array of the options section given of the same name
 *
 * @param jinfo
 *   The jcfg information structure pointer
 * @param name
 *   The string name of the array to search for in the default list.
 * @param val_arr
 *   Location to place the found object data array.
 * @return
 *   0 on success and *val_arr* is valid or -1 on error
 */
CNDP_API int jcfg_option_array_get(jcfg_info_t *jinfo, const char *name, obj_value_t **val_arr);

/**
 * Get the value of the options section given of the same name for a string value
 *
 * @param jinfo
 *   The jcfg information structure pointer
 * @param name
 *   The string name of the object to search for in the default list.
 * @param v
 *   Location to place the found object data.
 * @return
 *   0 on success and *val* is valid or -1 on error
 */
static inline int
jcfg_option_get_string(jcfg_info_t *jinfo, const char *name, char **v)
{
    uint64_t val;

    if (jcfg_option_get(jinfo, name, &val) < 0)
        return -1;
    *v = (char *)val;
    return 0;
}

/**
 * Load and parse a json-c or json file, socket or string.
 *
 * @param flags
 *   Flags used to configure jcfg JSON parsing.
 * @param s
 *   The json-c or json file or string to load and parse.
 *
 * @return
 *   The pointer to jcfg_info_t or NULL on error.
 */
CNDP_API jcfg_info_t *jcfg_parser(int flags, const char *s);

/**
 * Free the jcfg structure
 *
 * @param jinfo
 *   Pointer to jcfg_info_t structure to free.
 */
CNDP_API void jcfg_destroy(jcfg_info_t *jinfo);

/**
 * Decode the Application JSON file.
 *
 * @param jinfo
 *   The jcfg_info_t pointer from jcfg_create()
 * @param key
 *   The key to search for in the JSON data, if NULL use the root JSON object
 *   If Key is given then a user defined function must be provided.
 * @param arg
 *   Argument to use in func callback. If arg is NULL then jinfo is passed to callback.
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int jcfg_decode(jcfg_info_t *jinfo, const char *key, void *arg);

/********************************************************************
 * Routines to create and destroy a Unix Domain Socket for jcfg parsing
 */

/**
 * Create the thread and socket to listen for json configuration
 *
 * @param jinfo
 *   The struct jcfg_info pointer from jcfg_create().
 * @param runtime_dir
 *   The path to the runtime directory can be NULL to use the default path
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int jcfg_socket_create(jcfg_info_t *jinfo, const char *runtime_dir);

/**
 * Destroy the thread which is waiting for json configuration
 *
 * @param jinfo
 *   The struct jcfg_info pointer
 */
CNDP_API void jcfg_socket_destroy(jcfg_info_t *jinfo);

/********************************************************************
 * Routine to add, remove or find decoders for parsing jcfg sections
 */

/**
 * Add a decoder for the user part of the json-C file.
 *
 * @param section
 *   The section name to use for locating the JSON section to decode.
 * @param func
 *   The json_c_visit_userfunc pointer
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int jcfg_add_decoder(const char *section, json_c_visit_userfunc *func);

/**
 * Delete a decoder from the list
 *
 * @param section
 *   The section name to use for locating the JSON section to decode.
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int jcfg_del_decoder(const char *section);

/**
 * Get a decoder by section name
 *
 * @param section
 *   The section name to use for locating the JSON section to decode.
 * @return
 *   The json_c_visit_userfunc pointer if found else NULL
 */
CNDP_API json_c_visit_userfunc *jcfg_get_decoder(const char *section);

/********************************************************************
 * Helper routine(s) for accessing internal data or dumping information
 */

/**
 * Return the internal data pointer in struct jcfg.
 *
 * @param jinfo
 *   The jcfg_info_t pointer for the JCFG configuration
 * @return
 *   NULL on error or pointer to jcfg_data_t structure.
 */
CNDP_API jcfg_data_t *jcfg_get_data(jcfg_info_t *jinfo);

/**
 * Return the UMEM pointer for the given ID value.
 *
 * @param jinfo
 *   The jcfg information structure pointer.
 * @param idx
 *   The ID or index value to locate.
 * @return
 *   NULL if id is invalid or the jcfg_umem_t pointer.
 */
CNDP_API jcfg_umem_t *jcfg_umem_by_index(jcfg_info_t *jinfo, int idx);

/**
 * Return the memory address of the region in UMEM area.
 *
 * @param lport
 *   The jcfg_lport_t pointer for the lport.
 * @param objcnt
 *   The uint32_t variable to place the number of objcnt in the region.
 * @return
 *   The address for the lport region
 */
CNDP_API char *jcfg_lport_region(jcfg_lport_t *lport, uint32_t *objcnt);

/**
 * Set the JSON string data for parsing later
 *
 * @param jinfo
 *   The pointer created from jcfg_create().
 * @param str
 *   The pointer to JSON text, can be NULL to free resources.
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int jcfg_json_string_set(jcfg_info_t *jinfo, const char *str);

/**
 * Return the JSON object pointer for the given jcfg_info_t pointer.
 *
 * @param jinfo
 *   The jcfg_info_t pointer containing the JSON root object
 * @param key
 *   The key to search for in the JOSN object, can be NULL.
 * @return
 *   NULL on error or JSON object pointer, if key is NULL return root object.
 */
CNDP_API struct json_object *jcfg_object_by_name(jcfg_info_t *jinfo, const char *key);

/**
 * Return the lport pointer for the given ID value.
 *
 * @param jinfo
 *   The jcfg information structure pointer.
 * @param idx
 *   The ID or index value to locate.
 * @return
 *   NULL if id is invalid or the jcfg_lport_t pointer.
 */
CNDP_API jcfg_lport_t *jcfg_lport_by_index(jcfg_info_t *jinfo, int idx);

/**
 * Return the thread pointer for the given ID value.
 *
 * @param jinfo
 *   The jcfg information structure pointer.
 * @param idx
 *   The ID or index value to locate.
 * @return
 *   NULL if id is invalid or the jcfg_thd_t pointer.
 */
CNDP_API jcfg_thd_t *jcfg_thd_by_index(jcfg_info_t *jinfo, int idx);

/**
 * Dump out the json_object, by walking the object tree.
 *
 * @param obj
 *   Start dumping at this object
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int jcfg_dump_object(struct json_object *obj);

/**
 * Dump out the json_object by key, by walking the object tree.
 *
 * @param jinfo
 *   The jcfg_info_t pointer holding the json root object
 * @param key
 *   Start dumping at this key
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int jcfg_dump_at(jcfg_info_t *jinfo, const char *key);

/**
 * Dump out the json_object from the root, by walking the object tree.
 *
 * @param jinfo
 *   The jcfg_info_t pointer holding the json root object
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int jcfg_dump(jcfg_info_t *jinfo);

/**
 * Dump out some information about jcfg structures
 */
CNDP_API void jcfg_dump_info(void);

#ifdef __cplusplus
}
#endif

#endif /* _JCFG_H_ */
