/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <poll.h>                       // for pollfd, poll, POLLIN
#include <sys/stat.h>                   // for stat, chmod, mkdir, S_ISDIR
#include <fcntl.h>                      // for open, O_RDONLY
#include <string.h>                     // for strlen, strerror, memcpy, strcmp
#include <json-c/json_object.h>         // for json_object_object_get_ex
#include <json-c/json_tokener.h>        // for json_tokener_free, json_tokener
#include <stdio.h>                      // for NULL, printf, fprintf, size_t, snpr...
#include <stdlib.h>                     // for free, calloc, realloc
#include <unistd.h>                     // for close, read, getpid, unlink, usleep
#include <errno.h>                      // for errno
#include <pthread.h>                    // for pthread_barrier_wait, pthread_barri...
#include <stddef.h>                     // for offsetof
#include <sys/socket.h>                 // for accept, bind, listen, socket, AF_UNIX

#include "jcfg.h"
#include "jcfg_private.h"        // for jcfg, jcfg_client_t, jcfg_get_json_...
#include "jcfg_decode.h"         // for jcfg_list_add
#include "cne_log.h"             // for CNE_LOG_ERR, CNE_ERR_GOTO, CNE_NULL...

static int ident = 2; /* Used for indenting the debug output */

#ifdef JSON_TOKENER_ALLOW_TRAILING_CHARS
static int strict_flags = (JSON_TOKENER_STRICT | JSON_TOKENER_ALLOW_TRAILING_CHARS);
#else
static int strict_flags = JSON_TOKENER_STRICT;
#endif

#ifndef HAVE_JSON_TOKENER_GET_PARSE_END
#define json_tokener_get_parse_end(tok) ((tok)->char_offset)
#else
#define json_tokener_get_parse_end(tok) 0
#endif

jcfg_data_t *
jcfg_get_data(jcfg_info_t *jinfo)
{
    if (!jinfo || !jinfo->cfg)
        return NULL;

    return &((struct jcfg *)jinfo->cfg)->data;
}

int
jcfg_list_add(jcfg_list_t *lst, void *obj)
{
    int cnt = lst->cnt;
    int sz  = (cnt + 1);

    if (sz > lst->sz) {
        lst->list = realloc(lst->list, (sz * sizeof(void *)));
        if (!lst->list)
            CNE_ERR_RET("Unable to allocate memory for jcfg_list_t.list[]\n");
        lst->sz = sz;
    }
    lst->list[lst->cnt++] = obj;

    return cnt;
}

int
jcfg_num_objects(jcfg_info_t *j, jcfg_cb_type_t cbtype)
{
    struct jcfg *cfg;

    if (!j || !j->cfg)
        return -1;
    cfg = j->cfg;

    // clang-format off
    switch(cbtype) {
    case JCFG_APPLICATION_TYPE: return cfg->data.app_count;
    case JCFG_DEFAULT_TYPE: return cfg->data.default_count;
    case JCFG_OPTION_TYPE: return cfg->data.opt_count;
    case JCFG_LPORT_TYPE: return cfg->data.lport_count;
    case JCFG_THREAD_TYPE: return cfg->data.thread_count;
    case JCFG_UMEM_TYPE: return cfg->data.umem_count;
    case JCFG_LGROUP_TYPE: return cfg->data.lgroup_count;
    default:
        break;
    }
    // clang-format on
    return -1;
}

static int
jcfg_parse_json(jcfg_info_t *jinfo)
{
    struct json_object *obj;
    struct jcfg *cfg;
    struct json_tokener *tok;
    size_t start_pos, end_pos;
    char *str;

    if (!jinfo || !jinfo->cfg)
        return -1;
    cfg = jinfo->cfg;

    str = jcfg_get_json_string(cfg);
    tok = jcfg_get_json_token(cfg);
    if (!str || !tok)
        return -1;

    end_pos   = strlen(str);
    start_pos = 0;
    ident     = 0;
    obj       = NULL;
    while (start_pos != end_pos) {
        obj = json_tokener_parse_ex(tok, &str[start_pos], end_pos - start_pos);
        enum json_tokener_error jerr = json_tokener_get_error(tok);
        int parse_end                = json_tokener_get_parse_end(tok);

        if (jerr == json_tokener_continue)
            start_pos += json_tokener_get_parse_end(tok);
        else if (jerr == json_tokener_success) {
            cfg->root = obj;

            if (jinfo->flags & JCFG_INFO_VERBOSE)
                jcfg_dump_object(obj);

            start_pos += json_tokener_get_parse_end(tok);
        } else if (jerr != json_tokener_continue) {
            char *aterr = &str[start_pos + parse_end];
            int offset  = start_pos + parse_end;

            fflush(stdout);
            fprintf(stderr, "Failed at offset %d:%s:\n", offset, json_tokener_error_desc(jerr));
            fprintf(stderr, "%s\n", aterr);
            json_tokener_free(tok);
            cfg->tok = NULL;
            return -1;
        }
    }

    return 0;
}

static int
jcfg_load_file(jcfg_info_t *jinfo, const char *filename)
{
    char *str = NULL;
    char buf[DEFAULT_CHUNK_SIZE];
    size_t len = 0, tot = 0;
    int fd, n;

    if (!jinfo)
        return -1;

    if (!strcmp("-", filename))
        fd = fileno(stdin);
    else
        fd = open(filename, O_RDONLY, 0);
    if (fd < 0)
        goto err;

    while ((n = read(fd, buf, sizeof(buf)))) {
        if ((len + n) >= tot) {
            tot += DEFAULT_CHUNK_SIZE;
            str = (char *)realloc(str, tot);
            if (!str)
                goto err;
        }
        if (n > 0) {
            memcpy(&str[len], buf, n);
            len += n;
            str[len] = '\0';
        }
    }
    close(fd);

    jcfg_json_string_set(jinfo, str); /* str is strdup() in this function */

    free(str);

    return 0;

err:
    if (fd >= 0)
        close(fd);
    free(str);
    return -1;
}

int
jcfg_json_string_set(jcfg_info_t *jinfo, const char *str)
{
    struct jcfg *cfg;

    if (!jinfo)
        return -1;
    cfg = jinfo->cfg;

    /* Free any previous string that was allocated */
    if (cfg->str)
        free(cfg->str);
    cfg->str = NULL;

    if (str)
        cfg->str = strdup(str);

    return 0;
}

static jcfg_info_t *
jcfg_create(int flags)
{
    jcfg_info_t *jinfo;

    jinfo = calloc(1, sizeof(jcfg_info_t));
    if (jinfo) {
        struct jcfg *cfg;
        struct json_tokener *tok;
        jcfg_data_t *d;

        cfg = calloc(1, sizeof(struct jcfg));
        if (!cfg) {
            jcfg_destroy(jinfo);
            CNE_NULL_RET("Unable to allocate struct jcfg\n");
        }
        jinfo->cfg = cfg;

        d = &cfg->data;

        STAILQ_INIT(&d->application);
        STAILQ_INIT(&d->defaults);
        STAILQ_INIT(&d->options);
        STAILQ_INIT(&d->umems);
        STAILQ_INIT(&d->lports);
        STAILQ_INIT(&d->lgroups);
        STAILQ_INIT(&d->threads);
        STAILQ_INIT(&d->lport_groups);
        STAILQ_INIT(&d->users);

        jinfo->listen_sock = -1;
        jinfo->running     = -1;

        tok = json_tokener_new_ex(JSON_TOKENER_DEFAULT_DEPTH);
        if (!tok) {
            jcfg_destroy(jinfo);
            CNE_NULL_RET("Unable to parse JSON file\n");
        }
        cfg->tok     = tok;
        jinfo->flags = flags;

        json_tokener_set_flags(tok, (flags & JCFG_INFO_STRICT_FLAG) ? strict_flags : 0);
    }

    return jinfo;
}

/**
 * Load and parse a json-c or json file.
 *
 * @param flags
 *   Flags used to configure jcfg JSON parsing.
 * @param filename
 *   The json-c or json file to load and parse.
 *
 * @return
 *   The pointer to jcfg_info_t or NULL on error.
 */
static jcfg_info_t *
jcfg_parse_file(int flags, const char *filename)
{
    jcfg_info_t *jinfo;

    jinfo = jcfg_create(flags);
    if (!jinfo)
        CNE_ERR_GOTO(err, "JCFG create failed\n");
    if (jcfg_load_file(jinfo, filename) < 0)
        CNE_ERR_GOTO(err, "JCFG loadfile failed\n");

    return jinfo;
err:
    jcfg_destroy(jinfo);
    return NULL;
}

/**
 * Load and parse a json-c or json data from a socket.
 *
 * @param flags
 *   Flags used to configure jcfg JSON parsing.
 * @param runtime_dir
 *   The path to the runtime directory if NULL use default path.
 *
 * @return
 *   The pointer to jcfg_info_t or NULL on error.
 */
static jcfg_info_t *
jcfg_parse_socket(int flags, const char *runtime_dir)
{
    jcfg_info_t *jinfo;

    jinfo = jcfg_create(flags);
    if (!jinfo)
        CNE_ERR_GOTO(err, "JCFG create failed\n");
    if (jcfg_socket_create(jinfo, runtime_dir) < 0)
        CNE_ERR_GOTO(err, "JCFG socket create failed\n");

    return jinfo;
err:
    jcfg_destroy(jinfo);
    return NULL;
}

/**
 * Load and parse a json-c or json file.
 *
 * @param flags
 *   Flags used to configure jcfg JSON parsing.
 * @param str
 *   The json-c or json string to be parsed.
 *
 * @return
 *   The pointer to jcfg_info_t or NULL on error.
 */
static jcfg_info_t *
jcfg_parse_string(int flags, const char *str)
{
    jcfg_info_t *jinfo;

    jinfo = jcfg_create(flags);
    if (!jinfo)
        CNE_ERR_GOTO(err, "JCFG create failed\n");
    if (jcfg_json_string_set(jinfo, str) < 0)
        CNE_ERR_GOTO(err, "JCFG unable to use JSON string\n");

    return jinfo;
err:
    jcfg_destroy(jinfo);
    return NULL;
}

jcfg_info_t *
jcfg_parser(int flags, const char *s)
{
    jcfg_info_t *jinfo = NULL;

    if ((flags & JCFG_PARSE_STRING) && s && strlen(s) > 0)
        jinfo = jcfg_parse_string(flags, s);
    else if ((flags & JCFG_PARSE_FILE) && s && strlen(s) > 0)
        jinfo = jcfg_parse_file(flags, s);
    else if (flags & JCFG_PARSE_SOCKET)
        jinfo = jcfg_parse_socket(flags, s);

    if (jinfo) {
        if (jcfg_parse_json(jinfo) < 0)
            CNE_ERR_GOTO(err, "JCFG parse of json failed\n");
        if (jcfg_decode(jinfo, NULL, NULL) < 0)
            CNE_ERR_GOTO(err, "JCFG Decode failed\n");
    }
    return jinfo;

err:
    jcfg_destroy(jinfo);
    return NULL;
}

static inline void
_object_free(jcfg_hdr_t *hdr)
{
    // clang-format off
    switch(hdr->cbtype) {
    case JCFG_APPLICATION_TYPE ... JCFG_OPTION_TYPE:
        do {
            jcfg_opt_t *opt = (jcfg_opt_t *)hdr;

            if (opt->val.type == STRING_OPT_TYPE)
                free(opt->val.str);
            else if (opt->val.type == ARRAY_OPT_TYPE) {
                for (int i = 0; i < opt->val.array_sz; i++)
                    free(opt->val.arr[i]);
            }
        } while(0);
        break;
    case JCFG_UMEM_TYPE:
        jcfg_umem_free(hdr);
        break;
    case JCFG_LGROUP_TYPE:
        break;
    case JCFG_LPORT_TYPE:
        free(((jcfg_lport_t *)hdr)->netdev);
        free(((jcfg_lport_t *)hdr)->pmd_name);
        free(((jcfg_lport_t *)hdr)->umem_name);
        break;
    case JCFG_THREAD_TYPE:
        free(((jcfg_thd_t *)hdr)->thread_type);
        free(((jcfg_thd_t *)hdr)->group_name);
        free(((jcfg_thd_t *)hdr)->lport_names);
        free(((jcfg_thd_t *)hdr)->lports);
        break;
    case JCFG_USER_TYPE:
        break;
    default:
        free(hdr);
        return;
    }
    // clang-format on

    free(hdr->name);
    free(hdr->desc);
    free(hdr);
}

#define _foreach(_d, _o)                                           \
    do {                                                           \
        while (!STAILQ_EMPTY(&_d->_o)) {                           \
            jcfg_hdr_t *hdr = (jcfg_hdr_t *)STAILQ_FIRST(&_d->_o); \
                                                                   \
            STAILQ_REMOVE_HEAD(&_d->_o, next);                     \
            _object_free(hdr);                                     \
        }                                                          \
    } while (0)

void
jcfg_destroy(jcfg_info_t *jinfo)
{
    if (jinfo) {
        struct jcfg *cfg  = jinfo->cfg;
        jcfg_data_t *data = &cfg->data;

        if (jinfo->running)
            jcfg_socket_destroy(jinfo);

        if (cfg->tok)
            json_tokener_free(cfg->tok);
        free(cfg->str);

        if (data) {
            _foreach(data, application);
            _foreach(data, defaults);
            _foreach(data, options);
            _foreach(data, umems);
            _foreach(data, lports);
            _foreach(data, lgroups);
            _foreach(data, threads);
            _foreach(data, users);
            free(cfg);
        }
        free(jinfo);
    }
}

struct json_object *
jcfg_object_by_name(jcfg_info_t *jinfo, const char *key)
{
    struct jcfg *cfg;
    struct json_object *obj = NULL;

    if (!jinfo)
        return NULL;

    cfg = jinfo->cfg;
    if (cfg && cfg->root) {
        if (!key || strlen(key) == 0)
            return cfg->root;

        if (json_object_object_get_ex(cfg->root, key, &obj))
            return obj;
    }
    return obj;
}

static int
client_handler(jcfg_client_t *c)
{
    char *str = NULL;
    char buf[DEFAULT_CHUNK_SIZE];
    size_t len = 0, tot = 0;
    int n;

    if (!c)
        goto err;

    while ((n = read(c->s, buf, sizeof(buf)))) {
        if ((len + n) >= tot) {
            tot += DEFAULT_CHUNK_SIZE;
            str = (char *)realloc(str, tot);
            if (!str)
                goto err;
        }
        if (n > 0) {
            memcpy(&str[len], buf, n);
            len += n;
            str[len] = '\0';
        }
    }
    close(c->s);

    jcfg_json_string_set(c->info, str); /* str is strdup() in this function */

    free(str);

    return 0;

err:
    if (c && c->s > 0)
        close(c->s);
    free(str);
    return -1;
}

static void *
socket_listener(void *_c)
{
    jcfg_client_t *c = _c;
    jcfg_info_t *jinfo;
    struct pollfd fds = {0};

    if (!c || !c->info)
        return NULL;

    int ret = pthread_setname_np(pthread_self(), "jcfg-listener");
    if (ret)
        CNE_NULL_RET("Unable to set name for jcfg socket listener\n");

    jinfo          = c->info;
    jinfo->running = 1;

    while (jinfo->running > 0) {
        int s;

        fds.fd      = jinfo->listen_sock;
        fds.events  = POLLIN;
        fds.revents = 0;

        if (poll(&fds, 1, 250) < 0)
            break;

        if (fds.revents != POLLIN)
            continue;

        cne_printf("Accept a connection on %d\n", jinfo->listen_sock);

        s = accept(jinfo->listen_sock, NULL, NULL);
        if (s < 0) {
            CNE_ERR("Error with accept, jcfg_client thread quitting\n");
            continue;
        }
        cne_printf("Found a connection on %d\n", s);

        c->s = s;
        if (client_handler(c) == 0)
            break;
    }
    jinfo->running = -1; /* signal the listener has stopped */

    if (pthread_barrier_wait(&c->barrier) > 0)
        CNE_ERR("Failed to wait for barrier\n");

    close(c->s);

    return NULL;
}

int
jcfg_socket_create(jcfg_info_t *jinfo, const char *runtime_dir)
{
    jcfg_client_t *c = NULL;
    char buff[1024];
    pthread_t t;

    jinfo->listen_sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (jinfo->listen_sock < 0)
        CNE_ERR_RET("Error with socket creation, %s", strerror(errno));

    jinfo->sun.sun_family = AF_UNIX;
    if (!runtime_dir || strlen(runtime_dir) == 0)
        runtime_dir = "/var/run/cndp";

    char *str, *s;
    struct stat statBuf;

    snprintf(buff, sizeof(buff), "%s", runtime_dir);
    s = buff;
    while ((str = strtok(s, "/")) != NULL) {
        if (str != s) {
            str[-1] = '/';
        }
        if (stat(buff, &statBuf) == -1) {
            if (mkdir(buff, 0755) < 0)
                CNE_ERR_GOTO(leave, "couldn't create directory %s\n", buff);
        } else {
            if (!S_ISDIR(statBuf.st_mode))
                CNE_ERR_GOTO(leave, "couldn't create directory %s\n", buff);
        }
        s = NULL;
    }
    snprintf(jinfo->sun.sun_path, sizeof(jinfo->sun.sun_path), "%s/config.%d", runtime_dir,
             getpid());

    if (bind(jinfo->listen_sock, (void *)&jinfo->sun, sizeof(jinfo->sun)) < 0) {
        jinfo->sun.sun_path[0] = 0;
        CNE_ERR_GOTO(leave, "Error binding socket: %s", strerror(errno));
    }

    if (chmod(jinfo->sun.sun_path, 0666) < 0)
        CNE_ERR_GOTO(leave, "Error changing path permissions: %s", strerror(errno));

    if (listen(jinfo->listen_sock, 1) < 0)
        CNE_ERR_GOTO(leave, "Error calling listen for socket: %s", strerror(errno));

    c = calloc(1, sizeof(jcfg_client_t));
    if (!c)
        CNE_ERR_GOTO(leave, "Unable to allocate struct jcfg_client\n");

    c->s    = -1;
    c->info = jinfo;

    if (pthread_barrier_init(&c->barrier, NULL, 2))
        CNE_ERR_GOTO(leave, "Error initializing barrier\n");

    cne_printf(">>> Waiting for configuration on %s\n", jinfo->sun.sun_path);
    int ret = pthread_create(&t, NULL, socket_listener, c);
    if (ret)
        CNE_ERR_GOTO(error, "Unable to start socket_lister thread\n");

    if (pthread_barrier_wait(&c->barrier) > 0)
        CNE_ERR_GOTO(error, "Failed to wait on barrier\n");

    if (pthread_barrier_destroy(&c->barrier))
        CNE_ERR_GOTO(leave, "Error destroying barrier\n");
    free(c);

    jcfg_socket_destroy(jinfo);

    return 0;

error:
    if (pthread_barrier_destroy(&c->barrier))
        CNE_ERR("Error destroying barrier\n");
leave:
    free(c);
    jcfg_socket_destroy(jinfo);
    return -1;
}

void
jcfg_socket_destroy(jcfg_info_t *jinfo)
{
    if (!jinfo)
        return;

    if (jinfo->running > 0) {
        jinfo->running = 0;
        while (jinfo->running == 0)
            usleep(25000);
    }
    if (jinfo->sun.sun_path[0])
        unlink(jinfo->sun.sun_path);

    if (jinfo->listen_sock > 0) {
        close(jinfo->listen_sock);
        jinfo->listen_sock = -1;
    }
}

void
jcfg_dump_info(void)
{
    cne_printf("[magenta]obj_value_t[]              [magenta]size[]: [red]%ld[]\n",
               sizeof(obj_value_t));
    cne_printf("   [magenta]offset([green]type[]): [red]%ld[]       [magenta]size[]: [red]%ld[]\n",
               offsetof(obj_value_t, type), sizeof(obj_type_t));
    cne_printf("   [magenta]offset([green]array_size[]): [red]%ld[] [magenta]size[]: [red]%ld[]\n",
               offsetof(obj_value_t, array_sz), sizeof(uint16_t));
    cne_printf("   [magenta]offset([green]arr[]): [red]%ld[]        [magenta]size[]: [red]%ld[]\n",
               offsetof(obj_value_t, arr), sizeof(void *));
    cne_printf("[magenta]jcfg_hdr_t[]               [magenta]size[]: [red]%ld[]\n",
               sizeof(jcfg_hdr_t));
    cne_printf("[magenta]jcfg_opt_t[]               [magenta]size[]: [red]%ld[]\n",
               sizeof(jcfg_opt_t));
    cne_printf("[magenta]jcfg_umem_t[]              [magenta]size[]: [red]%ld[]\n",
               sizeof(jcfg_umem_t));
    cne_printf("[magenta]jcfg_lport_t[]             [magenta]size[]: [red]%ld[]\n",
               sizeof(jcfg_lport_t));
    cne_printf("[magenta]jcfg_thd_t[]               [magenta]size[]: [red]%ld[]\n",
               sizeof(jcfg_thd_t));
    cne_printf("[magenta]jcfg_user_t[]              [magenta]size[]: [red]%ld[]\n",
               sizeof(jcfg_user_t));
    cne_printf("[magenta]region_info_t[]            [magenta]size[]: [red]%ld[]\n",
               sizeof(region_info_t));
}
