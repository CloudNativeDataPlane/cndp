/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

// IWYU pragma: no_include <json-c/json_types.h>

#include <string.h>                    // for strcmp, strdup, strchr
#include <json-c/json_object.h>        // for json_object_get_string, json_object_...
#include <json-c/json_visit.h>         // for json_c_visit, JSON_C_VISIT_RETURN_CO...
#include <stdlib.h>                    // for NULL, calloc, free, size_t
#include <bsd/sys/queue.h>             // for STAILQ_INSERT_TAIL
#include <stdint.h>                    // for uint32_t

#include "jcfg.h"                // for jcfg_lport_t, jcfg_info_t, jcfg_data_t
#include "jcfg_private.h"        // for jcfg
#include "jcfg_decode.h"         // for jcfg_list_add, _decode_lports
#include "cne_common.h"          // for __cne_unused
#include "cne_log.h"             // for CNE_LOG_ERR, CNE_ERR, CNE_ERR_RET
#include "cne_strings.h"
#include "bpf/xsk.h"
#include "cne_lport.h"
#include "netdev_funcs.h"

/* The name of the umem used by default for all lport groups */
#define LPORT_GROUP_UMEM_NAME "lport-group"

/* Wrap strol to parse null-terminated string as u16 decimal value */
static int
parse_u16(const char *str, char **endp, uint16_t *value)
{
    long x;

    if (!str || !endp || !value)
        return -1;

    errno = 0;
    x     = strtol(str, endp, 10);
    if (errno || !*endp || *endp == str)
        return -1;

    if (x < 0 || x > USHRT_MAX)
        return -1;

    *value = (uint16_t)x;

    return 0;
}

/*
 * Check if characters are allowed to construct a range
 *
 * Make sure each character in the null-terminated input string is one
 * that is allowed to be used to construct a range of numbers.
 *
 * @param s
 *   The input string
 * @return
 *  0 if all characters in the input string are allowed, otherwise -1.
 */
static int
check_allowed_range_characters(const char *s)
{
    static const char *allow = "0123456789 -";
    const char *i, *j;

    for (i = s; *i != '\0'; i++) {
        for (j = allow; *j != '\0'; j++)
            if (*i == *j)
                break;
        /* The current character is not in the allowed list */
        if (*j == '\0')
            return -1;
    }

    return 0;
}

/*
 * Parse range values from a null-terminated string
 *
 * The range can have a single part or a low and high part. That means
 * both "1" and "1-2" are valid. The return value is used to determine
 * how many parts are parsed from the range.
 *
 * @param range
 *   The input string
 * @param v1
 *   The low part of a range, or the only part if there input string does
 *   not contain a hyphen.
 * @param v2
 *   The high part of a range.
 * @return
 *  -1 on error, 0 if only v1 is parsed, 1 if both v1 and v2 are parsed.
 */
static int
parse_range(const char *range, uint16_t *v1, uint16_t *v2)
{
    char *hyphen, *end = NULL;

    if (!range || !v1 || !v2)
        return -1;

    if (check_allowed_range_characters(range))
        return -1;

    if (parse_u16(range, &end, v1))
        return -1;

    /* Skip trailing spaces */
    for (; *end == ' '; end++)
        ;

    hyphen = strchr(range, '-');

    if (hyphen) {
        /* Ensure there are no extra digits in the range's low value. For
         * example "0 1-2" is invalid because "0 1" is not a number.
         */
        if (end != hyphen)
            return -1;

        end = NULL;
        if (parse_u16(hyphen + 1, &end, v2))
            return -1;

        /* Skip trailing spaces */
        for (; *end == ' '; end++)
            ;
    }

    /* Ensure there are no extra digits. For example, "1  1" and "0-1  1"
     * are invalid because "1  1" is not a number.
     */
    if (*end != '\0')
        return -1;

    if (hyphen) {
        /* Range low part must be less than the high part. For example "2-1"
         * is invalid
         */
        if (*v1 > *v2)
            return -1;

        /* Special case where both range parts are the same. For example
         * "2-2" is valid, but return as if a single part were parsed.
         */
        if (*v1 == *v2)
            hyphen = NULL;
    }

    /* Return 0 if only v1 is parsed, or 1 if both v1 and v2 are parsed */
    return hyphen ? 1 : 0;
}

static void
construct_queue_list(struct queue_list *qlist)
{
    TAILQ_INIT(&qlist->head);
}

static void
destruct_queue_list(struct queue_list *qlist)
{
    struct queue_list_entry *e, *tmp;

    TAILQ_FOREACH_SAFE (e, &qlist->head, next, tmp) {
        TAILQ_REMOVE(&qlist->head, e, next);
        free(e);
    }
}

static void
free_lport_group_obj(jcfg_lport_group_t *lpg)
{
    int i;

    if (!lpg)
        return;

    free(lpg->name);
    free(lpg->desc);
    if (lpg->netdev_names) {
        for (i = 0; i < lpg->num_netdev_names; i++)
            free(lpg->netdev_names[i]);
        free(lpg->netdev_names);
    }
    if (lpg->thread_names) {
        for (i = 0; i < lpg->num_thread_names; i++)
            free(lpg->thread_names[i]);
        free(lpg->thread_names);
    }
    free(lpg->max_q);
    free(lpg->pmd_name);
    free(lpg->umem_name);
    if (lpg->qlist) {
        destruct_queue_list(lpg->qlist);
        free(lpg->qlist);
    }
}

static int
setup_lport(jcfg_data_t *data, jcfg_lport_group_t *lpg, const char *netdev, uint16_t qid,
            jcfg_thd_t *thd)
{
    char name[CNE_NAME_LEN];
    jcfg_lport_t *lport;
    int ret;

    ret = snprintf(name, sizeof(name), "%s:%u", netdev, qid);
    if (ret < 3 || (size_t)ret >= sizeof(name))
        CNE_ERR_RET("Cannot configure name for netdev '%s' queue %u\n", netdev, qid);

    /* Make sure a logical port with this name or netdev:qid does not already exist */
    STAILQ_FOREACH (lport, &data->lports, next) {
        if (!strncmp(lport->name, name, CNE_NAME_LEN))
            CNE_ERR_RET("Logical port '%s' is already configured\n", name);

        if (!strncmp(lport->netdev, netdev, JCFG_MAX_STRING_SIZE) && lport->qid == qid)
            CNE_ERR_RET("Netdev '%s' queue %u is already configured\n", netdev, qid);
    }

    lport = calloc(1, sizeof(*lport));
    if (!lport)
        CNE_ERR_RET("Out of memory\n");

    ret = jcfg_list_add(&data->lport_list, lport);
    if (ret < 0) {
        free(lport);
        CNE_ERR_RET("Out of memory\n");
    }
    lport->lpid = ret;

    lport->cbtype = JCFG_LPORT_TYPE;
    lport->qid    = qid;
    lport->netdev = strdup(netdev);
    lport->name   = strdup(name);

    if (lpg->pmd_name)
        lport->pmd_name = strdup(lpg->pmd_name);
    /* TODO: this is problematic because the "normal" jcfg_lport decoder
     * creates a single string for pmd_name and pmd_opts, not two as is
     * the case here
     */
    if (lpg->pmd_opts)
        lport->pmd_opts = strdup(lpg->pmd_opts);
    lport->umem_name    = strdup(lpg->umem_name);
    lport->umem         = lpg->umem;
    lport->busy_timeout = lpg->busy_timeout;
    lport->busy_budget  = lpg->busy_budget;
    lport->flags        = lpg->flags;

    STAILQ_INSERT_TAIL(&data->lports, lport, next);
    data->lport_count++;

    /* Assign the lport to the thread */
    thd->lport_names[thd->lport_cnt] = strdup(name);
    thd->lports[thd->lport_cnt]      = lport;
    thd->lport_cnt++;
    return 0;
}

static int
setup_lports_with_qlist(jcfg_info_t *jinfo, jcfg_data_t *data, jcfg_lport_group_t *lpg)
{
    struct queue_list *qlist = (struct queue_list *)lpg->qlist;
    struct queue_list_entry *e;
    uint16_t count = 0;
    int i;

    for (i = 0; i < lpg->num_netdev_names; i++) {
        char *netdev = lpg->netdev_names[i];

        TAILQ_FOREACH (e, &qlist->head, next) {
            char *thread_name = lpg->thread_names[count % lpg->num_thread_names];
            jcfg_thd_t *thd   = jcfg_lookup_thread(jinfo, thread_name);

            if (!thd)
                CNE_ERR_RET("Thread '%s' not found\n", thread_name);

            if (setup_lport(data, lpg, netdev, e->v, thd))
                return -1;
            count++;
        }
    }

    if (count != lpg->total_q)
        CNE_ERR_RET("Assigned %d queues but expected %d\n", count, lpg->total_q);
    return 0;
}

static int
setup_lports_without_qlist(jcfg_info_t *jinfo, jcfg_data_t *data, jcfg_lport_group_t *lpg)
{
    uint16_t count = 0;
    int i;

    for (i = 0; i < lpg->num_netdev_names; i++) {
        char *netdev = lpg->netdev_names[i];
        uint16_t qid;

        for (qid = 0; qid < lpg->max_q[i]; qid++) {
            char *thread_name = lpg->thread_names[count % lpg->num_thread_names];
            jcfg_thd_t *thd   = jcfg_lookup_thread(jinfo, thread_name);

            if (!thd)
                CNE_ERR_RET("Thread '%s' not found\n", thread_name);

            if (setup_lport(data, lpg, netdev, qid, thd))
                return -1;
            count++;
        }
    }

    if (count != lpg->total_q)
        CNE_ERR_RET("Assigned %d queues but expected %d\n", count, lpg->total_q);
    return 0;
}

/*
 * Configure total number of queues based on each netdev's maximum
 *
 * Return total number of queues
 */
static uint16_t
total_queues_all(jcfg_lport_group_t *lpg)
{
    uint16_t total_q = 0;
    int i;

    /* Store maximum number of queues for each netdev */
    lpg->max_q = calloc(lpg->num_netdev_names, sizeof(*lpg->max_q));
    if (!lpg->max_q)
        CNE_ERR_RET_VAL(0, "Out of memory\n");

    for (i = 0; i < lpg->num_netdev_names; i++) {
        char *netdev = lpg->netdev_names[i];
        int num;

        num = netdev_get_channels(netdev);
        if (num < 0)
            CNE_ERR_RET_VAL(0, "Failed to get number of queues for netdev '%s'\n", netdev);

        if (num > USHRT_MAX) {
            CNE_WARN("Max queues truncated to %u for netdev '%s'\n", USHRT_MAX, netdev);
            num = USHRT_MAX;
        }

        lpg->max_q[i] = num;
        total_q += num;
    }

    return total_q;
}

/*
 * Create lport jcfg objects for each queue and assign to threads
 *
 * Note: this function (or ones it calls) may allocate memory that should be freed
 * by calling free_lport_group_obj() in case of error. The umem and lport jcfg
 * objects should also be cleaned up.
 */
static int
jcfg_decode_one_lport_group_end(jcfg_info_t *jinfo, jcfg_data_t *data, jcfg_lport_group_t *lpg)
{
    int i, qs_to_add;

    if (!lpg->num_netdev_names)
        CNE_ERR_RET("lport group '%s' needs at least one netdev\n", lpg->name);

    if (!lpg->num_thread_names)
        CNE_ERR_RET("lport group '%s' needs at least one thread\n", lpg->name);

    /* Verify threads exist */
    for (i = 0; i < lpg->num_thread_names; i++)
        if (!jcfg_lookup_thread(jinfo, lpg->thread_names[i]))
            CNE_ERR_RET("Thread '%s' not found\n", lpg->thread_names[i]);

    /* Setup total queues, using all queues from each netdev if no queue list is provided */
    if (!lpg->qlist)
        lpg->total_q = total_queues_all(lpg);
    else
        lpg->total_q = ((struct queue_list *)lpg->qlist)->num * lpg->num_netdev_names;

    if (!lpg->total_q)
        CNE_ERR_RET("lport group '%s' needs at least one queue\n", lpg->name);

    /* Assign a umem */
    if (!lpg->umem_name)
        CNE_ERR_RET("lport group '%s' needs a umem\n", lpg->name);

    /* The requested umem must already exist, unless the lport group uses the common umem,
     * which can only be created after all lport groups are processed.
     */
    lpg->umem = jcfg_lookup_umem(jinfo, lpg->umem_name);
    if (!lpg->umem && strncmp(lpg->umem_name, LPORT_GROUP_UMEM_NAME, JCFG_MAX_STRING_SIZE))
        CNE_ERR_RET("UMEM '%s' not found\n", lpg->umem_name);

    /* realloc() thd->lport_names and thd->lports arrays to accommodate new lports */
    qs_to_add = (lpg->total_q / lpg->num_thread_names) + (lpg->total_q % lpg->num_thread_names);
    for (i = 0; i < lpg->num_thread_names; i++) {
        jcfg_thd_t *thd = jcfg_lookup_thread(jinfo, lpg->thread_names[i]);

        if (!thd)
            CNE_ERR_RET("Thread '%s' not found\n", lpg->thread_names[i]);

        /* Each thread needs to account for a maximum to-be-assigned lports of
         * (total_q / num_threads) + (total_q % num_threads) in the worst case.
         */
        if ((thd->lport_sz - thd->lport_cnt) < qs_to_add) {
            void *p =
                realloc(thd->lport_names, (thd->lport_sz + qs_to_add) * sizeof(*thd->lport_names));
            if (!p)
                CNE_ERR_RET("Out of memory\n");
            thd->lport_names = p;

            p = realloc(thd->lports, (thd->lport_sz + qs_to_add) * sizeof(*thd->lports));
            if (!p)
                CNE_ERR_RET("Out of memory\n");
            thd->lports = p;
            thd->lport_sz += qs_to_add;
        }
    }

    /* create lport(s) and assign to thread(s) */
    if (lpg->qlist)
        return setup_lports_with_qlist(jinfo, data, lpg);
    else
        return setup_lports_without_qlist(jinfo, data, lpg);
}

static int
setup_common_umem(jcfg_info_t *jinfo, jcfg_data_t *data)
{
    uint32_t total_lport = 0;
    jcfg_lport_group_t *lpg;
    jcfg_lport_t *lport;
    jcfg_umem_t *umem;
    char *v = NULL;
    int idx;

    /* User can override the common umem by specifying parameters in the jcfg. If
     * this were the case, the lports will have already been assigned the umem.
     */
    if (jcfg_lookup_umem(jinfo, LPORT_GROUP_UMEM_NAME))
        return 0;

    /* Count total lports using the common umem */
    STAILQ_FOREACH (lport, &data->lports, next)
        if (!strncmp(lport->umem_name, LPORT_GROUP_UMEM_NAME, JCFG_MAX_STRING_SIZE))
            total_lport++;

    if (!total_lport)
        return 0;

    umem = calloc(1, sizeof(*umem));
    if (!umem)
        CNE_ERR_GOTO(err_out, "Out of memory\n");

    umem->name   = strdup(LPORT_GROUP_UMEM_NAME);
    umem->cbtype = JCFG_UMEM_TYPE;

    if (jcfg_default_get_u16(jinfo, "rxdesc", &umem->rxdesc))
        umem->rxdesc = LPORT_DFLT_RX_NUM_DESCS;
    else
        umem->rxdesc *= 1024;

    if (jcfg_default_get_u16(jinfo, "txdesc", &umem->txdesc))
        umem->txdesc = LPORT_DFLT_TX_NUM_DESCS;
    else
        umem->txdesc *= 1024;

    if (jcfg_default_get_u32(jinfo, "bufcnt", &umem->bufcnt))
        /* Estimate the number of buffers */
        umem->bufcnt = (umem->rxdesc * 3 + umem->txdesc * 3) * total_lport;
    else
        umem->bufcnt *= 1024;

    if (jcfg_default_get_u32(jinfo, "bufsz", &umem->bufsz))
        umem->bufsz = DEFAULT_MBUF_SIZE;
    else
        umem->bufsz *= 1024;

    if (jcfg_default_get_string(jinfo, "mtype", &v))
        umem->mtype = MMAP_HUGEPAGE_4KB;
    else
        umem->mtype = mmap_type_by_name((const char *)v);

    /* All lports use the same region */
    umem->rinfo = calloc(1, sizeof(*umem->rinfo));
    if (!umem->rinfo)
        CNE_ERR_GOTO(err_out, "Out of memory\n");

    umem->region_cnt      = 1;
    umem->rinfo[0].bufcnt = umem->bufcnt;

    /* add umem to list of all umems */
    idx = jcfg_list_add(&data->umem_list, umem);
    if (idx < 0)
        CNE_ERR_GOTO(err_out, "Out of memory\n");
    umem->idx = idx;

    STAILQ_INSERT_TAIL(&data->umems, umem, next);
    data->umem_count++;

    /* Assign the umem to each lport group using the common umem */
    STAILQ_FOREACH (lpg, &data->lport_groups, next)
        if (!strncmp(lpg->umem_name, LPORT_GROUP_UMEM_NAME, JCFG_MAX_STRING_SIZE))
            lpg->umem = umem;

    /* Assign the umem to each of the lports using the common umem */
    STAILQ_FOREACH (lport, &data->lports, next)
        if (!strncmp(lport->umem_name, LPORT_GROUP_UMEM_NAME, JCFG_MAX_STRING_SIZE))
            lport->umem = umem;

    return 0;

err_out:
    if (umem) {
        free(umem->rinfo);
        free(umem->name);
    }
    free(umem);
    return -1;
}

int
jcfg_decode_lport_groups_end(jcfg_info_t *jinfo, void *arg __cne_unused)
{
    jcfg_lport_group_t *lpg, *tmp;
    jcfg_data_t *data;

    if (!jinfo)
        return -1;

    data = &((struct jcfg *)jinfo->cfg)->data;

    STAILQ_FOREACH (lpg, &data->lport_groups, next)
        if (jcfg_decode_one_lport_group_end(jinfo, data, lpg))
            goto err_out;

    if (setup_common_umem(jinfo, data))
        goto err_out;

    return 0;

err_out:
    STAILQ_FOREACH_SAFE(lpg, &data->lport_groups, next, tmp)
    {
        free_lport_group_obj(lpg);
        free(lpg);
    }
    return -1;
}

/*
 * Add an element to an ascending ordered TAILQ without duplicates.
 * If a value to add already exists, it is skipped.
 */
static void
add_to_queue_list(struct queue_list *ql, uint16_t value)
{
    struct queue_list_entry *e, *i;

    if (!ql)
        return;

    e = calloc(1, sizeof(*e));
    if (!e)
        return;

    e->v = value;

    if (ql->num) {
        if (value < ql->min) {
            TAILQ_INSERT_HEAD(&ql->head, e, next);
            ql->num++;
            ql->min = value;
            return;
        } else if (value > ql->max) {
            TAILQ_INSERT_TAIL(&ql->head, e, next);
            ql->num++;
            ql->max = value;
            return;
        }
    } else {
        TAILQ_INSERT_TAIL(&ql->head, e, next);
        ql->num = 1;
        ql->min = value;
        ql->max = value;
        return;
    }

    /* value needs to be added somewhere other than head or tail. */
    TAILQ_FOREACH (i, &ql->head, next) {
        if (value == i->v) {
            /* already added */
            free(e);
            return;
        }
        if (value < i->v) {
            TAILQ_INSERT_BEFORE(i, e, next);
            ql->num++;
            return;
        }
    }
}

static int
decode_lport_group_queues_array(jcfg_lport_group_t *lpg, struct json_object *arr)
{
    int i, arrlen = json_object_array_length(arr);

    for (i = 0; i < arrlen; i++) {
        struct json_object *obj = json_object_array_get_idx(arr, i);

        if (json_object_get_type(obj) == json_type_string) {
            const char *str = json_object_get_string(obj);
            uint16_t low, high;
            int ret;

            ret = parse_range(str, &low, &high);
            if (ret < 0)
                CNE_ERR_RET("Failed to decode queues array element '%s'\n", str);

            if (!ret)
                high = low;

            for (; low <= high; low++)
                add_to_queue_list(lpg->qlist, low);
        } else if (json_object_get_type(obj) == json_type_int) {
            int queue = json_object_get_int(obj);

            if (queue < 0 || queue > USHRT_MAX)
                CNE_ERR_RET("Queue %d is out of range \"0-%d\"\n", queue, USHRT_MAX);

            add_to_queue_list(lpg->qlist, queue);
        } else
            CNE_ERR_RET("Unknown queues array object type '%s'\n",
                        json_type_to_name(json_object_get_type(obj)));
    }

    return 0;
}

static int
decode_lport_group_queues(jcfg_lport_group_t *lpg, struct json_object *obj)
{
    uint16_t low, high;

    if (lpg->qlist)
        CNE_ERR_RET("%s can only be configured once\n", JCFG_LPORT_GROUP_QUEUES_NAME);

    lpg->qlist = calloc(1, sizeof(struct queue_list));
    if (!lpg->qlist)
        CNE_ERR_RET("Out of memory\n");
    construct_queue_list(lpg->qlist);

    if (json_object_get_type(obj) == json_type_string) {
        const char *str = json_object_get_string(obj);
        int ret;

        /* "all" or single value like "8" or range like "1-4" */
        if (!strncmp(str, "all", 3)) {
            destruct_queue_list(lpg->qlist);
            free(lpg->qlist);
            lpg->qlist = NULL;
            return 0;
        }

        ret = parse_range(str, &low, &high);
        if (ret < 0)
            CNE_ERR_GOTO(err_out, "Failed to decode queues\n");

        if (!ret)
            high = low;

        for (; low <= high; low++)
            add_to_queue_list(lpg->qlist, low);
    } else if (json_object_get_type(obj) == json_type_int) {
        int queue = json_object_get_int(obj);

        if (queue < 0 || queue > USHRT_MAX)
            CNE_ERR_GOTO(err_out, "Queue %d is out of range \"0-%d\"\n", queue, USHRT_MAX);

        add_to_queue_list(lpg->qlist, queue);
    } else if (json_object_get_type(obj) == json_type_array) {
        if (decode_lport_group_queues_array(lpg, obj))
            CNE_ERR_GOTO(err_out, "Failed to decode queues array\n");
    } else {
        CNE_ERR_GOTO(err_out, "Failed to decode queues object with type '%s'\n",
                     json_type_to_name(json_object_get_type(obj)));
    }

    return 0;
err_out:
    destruct_queue_list(lpg->qlist);
    free(lpg->qlist);
    lpg->qlist = NULL;
    return -1;
}

static int
_lport_group(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
             const char *key, size_t *index __cne_unused, void *arg)
{
    jcfg_lport_group_t *lpg = (jcfg_lport_group_t *)arg;
    size_t keylen;

    if (flags == JSON_C_VISIT_SECOND)
        return JSON_C_VISIT_RETURN_CONTINUE;

    /* TODO: test for proper type (object, array, etc.) */
    if (!key)
        return JSON_C_VISIT_RETURN_CONTINUE;

    keylen = strnlen(key, JCFG_MAX_STRING_SIZE);
    if (!strncmp(key, JCFG_LPORT_PMD_NAME, keylen)) {
        char *pmd_str    = strdup(json_object_get_string(obj));
        char *pmd_opt[2] = {0};

        if (pmd_str) {
            cne_strtok(pmd_str, ":", pmd_opt, 2);
            lpg->pmd_name = pmd_opt[0] ? pmd_opt[0] : pmd_str;
            lpg->pmd_opts = pmd_opt[1];
        }
    } else if (!strncmp(key, JCFG_LPORT_UMEM_NAME, keylen))
        lpg->umem_name = strndup(json_object_get_string(obj), JCFG_MAX_STRING_SIZE);
    else if (!strncmp(key, JCFG_LPORT_DESC_NAME, keylen) ||
             !strncmp(key, JCFG_LPORT_DESCRIPTION_NAME, keylen))
        lpg->desc = strdup(json_object_get_string(obj));
    else if (!strncmp(key, JCFG_LPORT_BUSY_TIMEOUT_NAME, keylen)) {
        int val;

        val = json_object_get_int(obj);
        if (val < 0 || val > USHRT_MAX)
            CNE_ERR_RET_VAL(JSON_C_VISIT_RETURN_ERROR, "%s: Invalid Range\n",
                            JCFG_LPORT_BUSY_TIMEOUT_NAME);
        lpg->busy_timeout = (uint16_t)val;
    } else if (!strncmp(key, JCFG_LPORT_BUSY_BUDGET_NAME, keylen)) {
        int val;

        val = json_object_get_int(obj);
        if (val < 0 || val > USHRT_MAX)
            CNE_ERR_RET_VAL(JSON_C_VISIT_RETURN_ERROR, "%s: Invalid Range\n",
                            JCFG_LPORT_BUSY_BUDGET_NAME);
        lpg->busy_budget = (uint16_t)val;
    } else if (!strncmp(key, JCFG_LPORT_UNPRIVILEGED_NAME, keylen))
        lpg->flags |= json_object_get_boolean(obj) ? LPORT_UNPRIVILEGED : 0;
    else if (!strncmp(key, JCFG_LPORT_FORCE_WAKEUP_NAME, keylen))
        lpg->flags |= json_object_get_boolean(obj) ? LPORT_FORCE_WAKEUP : 0;
    else if (!strncmp(key, JCFG_LPORT_SKB_MODE_NAME, keylen))
        lpg->flags |= json_object_get_boolean(obj) ? LPORT_SKB_MODE : 0;
    else if (!strncmp(key, JCFG_LPORT_BUSY_POLL_NAME, keylen) ||
             !strncmp(key, JCFG_LPORT_BUSY_POLLING_NAME, keylen))
        lpg->flags |= json_object_get_boolean(obj) ? LPORT_BUSY_POLLING : 0;
    else if (!strncmp(key, JCFG_LPORT_GROUP_NETDEV_NAMES_NAME, keylen)) {
        int i, arrlen = json_object_array_length(obj);

        lpg->netdev_names = calloc(arrlen, sizeof(*lpg->netdev_names));
        if (!lpg->netdev_names)
            return JSON_C_VISIT_RETURN_ERROR;

        for (i = 0; i < arrlen; i++) {
            struct json_object *val = json_object_array_get_idx(obj, i);

            lpg->netdev_names[i] = strdup(json_object_get_string(val));
        }
        lpg->num_netdev_names = arrlen;
    } else if (!strncmp(key, JCFG_LPORT_GROUP_THREAD_NAMES_NAME, keylen)) {
        int i, arrlen = json_object_array_length(obj);

        lpg->thread_names = calloc(arrlen, sizeof(*lpg->netdev_names));
        if (!lpg->thread_names)
            return JSON_C_VISIT_RETURN_ERROR;

        for (i = 0; i < arrlen; i++) {
            struct json_object *val = json_object_array_get_idx(obj, i);

            lpg->thread_names[i] = strdup(json_object_get_string(val));
        }
        lpg->num_thread_names = arrlen;
    } else if (!strncmp(key, JCFG_LPORT_GROUP_QUEUES_NAME, keylen)) {
        if (decode_lport_group_queues(lpg, obj))
            CNE_ERR_RET_VAL(JSON_C_VISIT_RETURN_ERROR, "%s: Invalid queues\n",
                            JCFG_LPORT_GROUP_QUEUES_NAME);
    } else
        CNE_WARN("Unknown lport group key (%s)\n", key);

    if (!lpg->umem_name)
        lpg->umem_name = strdup(LPORT_GROUP_UMEM_NAME);

    return JSON_C_VISIT_RETURN_CONTINUE;
}

static int
_lport_group_obj(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
                 const char *key, size_t *index __cne_unused, void *arg)
{
    jcfg_info_t *jinfo = (jcfg_info_t *)arg;
    int ret            = JSON_C_VISIT_RETURN_CONTINUE;
    jcfg_lport_group_t *lpg;
    jcfg_data_t *data;

    if (flags == JSON_C_VISIT_SECOND)
        return ret;

    if (!key || json_object_get_type(obj) != json_type_object)
        return ret;

    lpg = calloc(1, sizeof(jcfg_lport_group_t));
    if (!lpg)
        return JSON_C_VISIT_RETURN_ERROR;

    lpg->name   = strdup(key);
    lpg->cbtype = JCFG_LPORT_GROUP_TYPE;

    ret = json_c_visit(obj, 0, _lport_group, lpg);
    if (ret != JSON_C_VISIT_RETURN_CONTINUE) {
        free_lport_group_obj(lpg);
        free(lpg);
        return ret;
    }

    data = &((struct jcfg *)jinfo->cfg)->data;
    STAILQ_INSERT_TAIL(&data->lport_groups, lpg, next);
    data->lport_group_count++;

    if (jinfo->flags & JCFG_DEBUG_DECODING) {
        int i;

        cne_printf("   '[cyan]%-10s[]': [green]netdevs[] [magenta]%d[] [ ", lpg->name,
                   lpg->num_netdev_names);

        for (i = 0; i < lpg->num_netdev_names; i++)
            cne_printf("'[magenta]%s[]' ", lpg->netdev_names[i]);

        if (lpg->qlist) {
            struct queue_list *qlist = (struct queue_list *)lpg->qlist;
            struct queue_list_entry *e;

            cne_printf("], [green]queues[] [magenta]%d[] [ ", qlist->num);

            TAILQ_FOREACH (e, &qlist->head, next)
                cne_printf("[magenta]%u[] ", e->v);
        }

        cne_printf("], [green]threads[] [magenta]%d[] [ ", lpg->num_thread_names);

        for (i = 0; i < lpg->num_thread_names; i++)
            cne_printf("'[magenta]%s[]' ", lpg->thread_names[i]);

        if (lpg->desc)
            cne_printf("], [green]desc[]:'[yellow]%s[]'\n", lpg->desc);
        else
            cne_printf("]\n");
    }

    return ret;
}

int
_decode_lport_groups(struct json_object *obj, int flags, struct json_object *parent __cne_unused,
                     const char *key, size_t *index __cne_unused, void *arg)
{
    jcfg_info_t *jinfo = (jcfg_info_t *)arg;
    enum json_type type;
    int ret;

    if (flags == JSON_C_VISIT_SECOND)
        return JSON_C_VISIT_RETURN_CONTINUE;

    type = json_object_get_type(obj);

    if (type != json_type_object)
        return JSON_C_VISIT_RETURN_ERROR;

    if (jinfo->flags & JCFG_DEBUG_DECODING)
        cne_printf("[magenta]%s[]: {\n", key);

    ret = json_c_visit(obj, 0, _lport_group_obj, arg);
    if (ret == JSON_C_VISIT_RETURN_ERROR)
        CNE_ERR("Parsing lport group failed\n");

    if (jinfo->flags & JCFG_DEBUG_DECODING)
        cne_printf("}\n");

    return ret ? ret : JSON_C_VISIT_RETURN_SKIP;
}
