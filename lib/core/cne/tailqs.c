/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2010-2022 Intel Corporation
 */

#include <sys/queue.h>
#include <stdio.h>
#include <string.h>
#include <bsd/string.h>

#include <cne_common.h>
#include <cne_log.h>
#include <cne_mutex_helper.h>

#include <cne_tailq.h>

static pthread_once_t once = PTHREAD_ONCE_INIT;

TAILQ_HEAD(cne_tailq_elem_head, cne_tailq_elem);

/* local tailq list */
static struct cne_tailq_elem_head cne_tailq_elem_head = TAILQ_HEAD_INITIALIZER(cne_tailq_elem_head);

static struct cne_tailq_head tailq_head[CNE_MAX_TAILQS];

/* number of tailqs registered, -1 before call to cne_tailqs_init */
static int cne_tailqs_count = -1;

static pthread_mutex_t tailq_list_mutex;

static inline void
tailq_lock(void)
{
    int ret = pthread_mutex_lock(&tailq_list_mutex);

    if (ret)
        CNE_WARN("failed: %s\n", strerror(ret));
}

static inline void
tailq_unlock(void)
{
    int ret = pthread_mutex_unlock(&tailq_list_mutex);

    if (ret)
        CNE_WARN("failed: %s\n", strerror(ret));
}

struct cne_tailq_head *
cne_tailq_lookup(const char *name)
{
    unsigned i;

    if (name == NULL)
        return NULL;

    tailq_lock();
    for (i = 0; i < CNE_MAX_TAILQS; i++) {
        if (!strncmp(name, tailq_head[i].name, CNE_TAILQ_NAMESIZE - 1)) {
            tailq_unlock();
            return &tailq_head[i];
        }
    }
    tailq_unlock();

    return NULL;
}

void
cne_dump_tailq(void)
{
    tailq_lock();
    for (int i = 0; i < CNE_MAX_TAILQS; i++) {
        const struct cne_tailq_head *tailq      = &tailq_head[i];
        const struct cne_tailq_entry_head *head = &tailq->tailq_head;

        printf("Tailq %u: qname:<%s>, tqh_first:%p, tqh_last:%p\n", i, tailq->name, head->tqh_first,
               head->tqh_last);
    }
    tailq_unlock();
}

static struct cne_tailq_head *
cne_tailq_create(const char *name)
{
    struct cne_tailq_head *head = NULL;

    tailq_lock();
    if (!cne_tailq_lookup(name) && (cne_tailqs_count + 1 < CNE_MAX_TAILQS)) {
        head = &tailq_head[cne_tailqs_count];
        strlcpy(head->name, name, sizeof(head->name) - 1);
        TAILQ_INIT(&head->tailq_head);
        cne_tailqs_count++;
    }
    tailq_unlock();

    return head;
}

/* local register, used to store "early" tailqs before cne_init() and to
 * only registers tailqs once.
 */
static int
cne_tailq_local_register(struct cne_tailq_elem *t)
{
    struct cne_tailq_elem *temp;

    TAILQ_FOREACH (temp, &cne_tailq_elem_head, next) {
        if (!strncmp(t->name, temp->name, sizeof(temp->name)))
            return -1;
    }

    TAILQ_INSERT_TAIL(&cne_tailq_elem_head, t, next);
    return 0;
}

static void
cne_tailq_update(struct cne_tailq_elem *t)
{
    t->head = cne_tailq_create(t->name);
}

int
cne_tailq_register(struct cne_tailq_elem *t)
{
    tailq_lock();
    if (cne_tailq_local_register(t) < 0)
        CNE_ERR_GOTO(error, "%s tailq is already registered\n", t->name);

    /* if a register happens after cne_tailqs_init(), then we can update
     * tailq head */
    if (cne_tailqs_count >= 0) {
        cne_tailq_update(t);
        if (t->head == NULL) {
            TAILQ_REMOVE(&cne_tailq_elem_head, t, next);
            CNE_ERR_GOTO(error, "Cannot initialize tailq: %s\n", t->name);
        }
    }
    tailq_unlock();

    return 0;

error:
    t->head = NULL;
    tailq_unlock();
    return -1;
}

static void
tailqs_init(void)
{
    struct cne_tailq_elem *t;

    tailq_lock();
    cne_tailqs_count = 0;

    TAILQ_FOREACH (t, &cne_tailq_elem_head, next) {
        /* second part of register job for "early" tailqs, see
         * cne_tailq_register and CNE_REGISTER_TAILQ */
        cne_tailq_update(t);
        if (t->head == NULL) {
            CNE_ERR("tailq update failed, dump list\n");
            cne_dump_tailq();
            break;
        }
    }
    tailq_unlock();
}

int
cne_tailqs_init(void)
{
    return pthread_once(&once, tailqs_init);
}

CNE_INIT(tailq_constructor)
{
    if (cne_mutex_create(&tailq_list_mutex, PTHREAD_MUTEX_RECURSIVE))
        CNE_ERR("creating recursive mutex failed\n");
}
