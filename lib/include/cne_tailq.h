/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#ifndef _CNE_TAILQ_H_
#define _CNE_TAILQ_H_

/**
 * @file
 *
 * Defines cne_tailq APIs to safely iterate over a list of items or structures. The tailq APIs
 * add non-list items to a tailq list. Add items to a tailq list by allocating a cne_tailq_entry
 * structure and adding the structure pointer to the cne_tailq_entry.data member. The calling
 * function must supply protection against multiple accesses to a given cne_tailq list.
 */

#include <sys/queue.h>
#include <stdio.h>

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/** dummy structure type used by the cne_tailq APIs */
struct cne_tailq_entry {
    TAILQ_ENTRY(cne_tailq_entry) next; /**< Pointer entries for a tailq list */
    void *data;                        /**< Pointer to the data referenced by this tailq entry */
};
/** dummy */
TAILQ_HEAD(cne_tailq_entry_head, cne_tailq_entry);

#define CNE_MAX_TAILQS     32
#define CNE_TAILQ_NAMESIZE 32

/**
 * The structure defining a tailq header entry. Each tailq
 * is identified by name.
 * Any library storing a set of objects e.g. rings, mempools, hash-tables,
 * is recommended to use an entry here.
 */
struct cne_tailq_head {
    struct cne_tailq_entry_head tailq_head; /**< NOTE: must be first element */
    char name[CNE_TAILQ_NAMESIZE];
};

struct cne_tailq_elem {
    /**
     * Reference to head in shared mem, updated at init time.
     */
    struct cne_tailq_head *head;
    TAILQ_ENTRY(cne_tailq_elem) next;
    const char name[CNE_TAILQ_NAMESIZE];
};

#define CNE_REGISTER_TAILQ(t)                                   \
    CNE_INIT(tailqinitfn_##t)                                   \
    {                                                           \
        if (cne_tailq_register(&t) < 0)                         \
            cne_panic("Cannot initialize tailq: %s\n", t.name); \
    }

/**
 * Return the first tailq entry cast to the right struct.
 */
#define CNE_TAILQ_CAST(tailq_entry, struct_name) (struct struct_name *)&(tailq_entry)->tailq_head

/**
 * Utility macro to make looking up a tailqueue for a particular struct easier.
 *
 * @param name
 *   The name of tailq
 *
 * @param struct_name
 *   The name of the list type we are using. (Generally this is the same as the
 *   first parameter passed to TAILQ_HEAD macro)
 *
 * @return
 *   The return value, typecast to the appropriate
 *   structure pointer type.
 *   NULL on error, since the tailq_head is the first
 *   element in the cne_tailq_head structure.
 */
#define CNE_TAILQ_LOOKUP(name, struct_name) CNE_TAILQ_CAST(cne_tailq_lookup(name), struct_name)

/**
 * Initialize the tailq structures.
 *
 * @return
 *   0 on success, -1 on error code
 */
CNDP_API int cne_tailqs_init(void);

/**
 * Register the given tailq entry.
 *
 * @param t
 *   The tailq element to register.
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cne_tailq_register(struct cne_tailq_elem *t);

/**
 * Dump tail queues to stdout.
 *
 */
CNDP_API void cne_dump_tailq(void);

/**
 * Lookup for a tail queue.
 *
 * Get a pointer to a tail queue header of a tail
 * queue identified by the name given as an argument.
 * Note: this function is not multi-thread safe, and should only be called from
 * a single thread at a time
 *
 * @param name
 *   The name of the queue.
 * @return
 *   A pointer to the tail queue head structure.
 */
CNDP_API struct cne_tailq_head *cne_tailq_lookup(const char *name);

/**
 * Register a tail queue.
 *
 * Register a tail queue from shared memory.
 * This function is mainly used by some, which is used to
 * register tailq from the different cndp libraries. Since this macro is a
 * constructor.
 *
 * @param t
 *   The tailq element which contains the name of the tailq you want to
 *   create (/retrieve when in secondary process).
 * @return
 *   0 on success or -1 in case of an error.
 */
CNDP_API int cne_eal_tailq_register(struct cne_tailq_elem *t);

/**
 * This macro permits both remove and free var within the loop safely.
 */
#ifndef TAILQ_FOREACH_SAFE
// clang-format off
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)      \
    for ((var) = TAILQ_FIRST((head));           \
        (var) && ((tvar) = TAILQ_NEXT((var), field), 1);    \
        (var) = (tvar))
// clang-format on
#endif

#ifdef __cplusplus
}
#endif

#endif /* _CNE_TAILQ_H_ */
