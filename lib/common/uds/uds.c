/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 */

// IWYU pragma: no_include <bits/struct_stat.h>
// IWYU pragma: no_include <bits/types/struct_iovec.h>

#include <stdio.h>              // for snprintf, NULL, size_t, perror
#include <stdbool.h>            // for bool, false, true
#include <unistd.h>             // for close, getpid, unlink, usleep
#include <stdlib.h>             // for free, calloc, malloc, realloc
#include <stdarg.h>             // for va_end, va_list, va_start
#include <pthread.h>            // for pthread_rwlock_unlock, pthread_...
#include <sys/socket.h>         // for msghdr, socket, AF_UNIX, accept
#include <sys/un.h>             // for sockaddr_un
#include <sys/stat.h>           // for stat, chmod, mkdir, S_ISDIR
#include <bsd/string.h>         // for strlcpy, strlcat
#include <poll.h>               // for pollfd, poll, POLLIN
#include <cne_version.h>        // for cne_version
#include <errno.h>              // for errno, EINVAL, ENAMETOOLONG
#include <limits.h>             // for PATH_MAX
#include <string.h>             // for strerror, strtok_r, strchr, str...
#include <strings.h>            // for strncasecmp
#include <cne_common.h>         // for CNE_USED, CNE_PTR_ADD, CNE_INIT
#include <cne_tailq.h>          // for TAILQ_FOREACH_SAFE
#include <ctype.h>              // for isalnum
#include <sys/queue.h>          // for TAILQ_INSERT_TAIL, TAILQ_FOREACH

#include "uds.h"

#define UDS_EXTRA_SPACE         64
#define UDS_MAX_BUF_LEN         (16 * 1024)
#define UDS_DEFAULT_RUNTIME_DIR "/var/run/cndp"

static int list_cmd(uds_client_t *c, const char *cmd, const char *params);
static int info_cmd(uds_client_t *c, const char *cmd, const char *params);

#define POLL_TIMEOUT 250

struct group_entry {
    TAILQ_ENTRY(group_entry) next; /**< TAILQ entry */
    struct uds_group group;        /**< UDS group information */
    const struct uds_info *info;   /**< UDS socket this group belongs to */
};

struct cmd_entry {
    TAILQ_ENTRY(cmd_entry) next;  /**< TAILQ entry */
    const struct group_entry *ge; /**< UDS group this command belongs to */
    char cmd[UDS_MAX_CMD_LEN];    /**< UDS command (not including group) */
    uds_cb fn;                    /**< User callback function */
};

static struct group_list {
    TAILQ_HEAD(, group_entry) list;
} group_list;

static struct cmd_list {
    TAILQ_HEAD(, cmd_entry) list;
} clb_list;

static pthread_rwlock_t lck = PTHREAD_RWLOCK_INITIALIZER;
static char uds_log_error[4096];
static uds_info_t *default_info;

static bool
is_root_group(const struct group_entry *ge)
{
    /* check if group name is empty */
    return ge->group.name[0] == '\0';
}

static void
get_group_name(const char *src, char *dst, size_t dst_len)
{
    const char *grp_end, *grp_start;

    /* terminate in case we don't find anything */
    dst[0] = '\0';

    /*
     * calling code should have terminated src and should have already checked
     * if first character is not a null byte, so we can assume that src[1] has
     * at least a null byte.
     */
    grp_start = CNE_PTR_ADD(src, 1);

    /* find second forward slash */
    grp_end = strchr(grp_start, '/');

    /* if second backslash is found, we have a group */
    if (grp_end != NULL) {
        /* start from after slash */
        size_t len = CNE_PTR_DIFF(grp_end, grp_start);
        /* protect from overflows and ensure termination */
        len = CNE_MIN(len, dst_len - 1);
        /* strlcpy always terminates, and size must include null byte */
        len++;
        strlcpy(dst, grp_start, len);
    }
}

static const struct group_entry *
find_group_by_name(const struct uds_info *info, const char *name)
{
    struct group_entry *cur;

    TAILQ_FOREACH (cur, &group_list.list, next) {
        if (cur->info != info)
            continue;
        if (strncasecmp(cur->group.name, name, sizeof(cur->group.name)) == 0)
            return cur;
    }

    return NULL;
}

static struct group_entry *
find_group_by_handle(const struct uds_group *grp)
{
    struct group_entry *cur;

    TAILQ_FOREACH (cur, &group_list.list, next) {
        /* group handles are unique, so no need to check uds_info_t */
        if (&cur->group == grp)
            return cur;
    }

    return NULL;
}

static const struct group_entry *
find_group_by_cmd(const struct uds_info *info, const char *cmd)
{
    char grp_name[UDS_MAX_GRP_NAME_LEN];

    if (!cmd || cmd[0] != '/')
        return NULL;

    /* extract group name from cmd */
    get_group_name(cmd, grp_name, sizeof(grp_name));

    return find_group_by_name(info, grp_name);
}

/*
 * find a command in the list of callbacks
 *
 * @params cmd
 *    The command string to search in the callback list case-insensitive
 * @return
 *    returns the index of the matching command of -1 if not found
 */
static struct cmd_entry *
find_command(const char *cmd, const struct group_entry *group)
{
    struct cmd_entry *cur;

    if (cmd == NULL || cmd[0] != '/')
        return NULL;

    TAILQ_FOREACH (cur, &clb_list.list, next) {
        /* does group match? */
        if (cur->ge != group)
            continue;
        if (strncasecmp(cmd, cur->cmd, sizeof(cur->cmd)) == 0)
            return cur;
    }
    return NULL;
}

static struct cmd_entry *
create_command(const char *cmd, struct group_entry *ge, uds_cb fn)
{
    struct cmd_entry *cb;

    cb = malloc(sizeof(*cb));
    if (cb == NULL) {
        errno = ENOMEM;
        goto err;
    }

    /* did it fit? */
    if (strlcpy(cb->cmd, cmd, sizeof(cb->cmd)) >= sizeof(cb->cmd)) {
        errno = ENAMETOOLONG;
        goto err;
    }

    cb->fn = fn;
    cb->ge = ge;

    return cb;

err:
    if (cb != NULL)
        free(cb);
    return NULL;
}

static struct group_entry *
create_group(const struct uds_info *info, const char *name, void *priv)
{
    struct group_entry *ge;
    const size_t sz = sizeof(ge->group.name);

    ge = malloc(sizeof(*ge));
    if (ge == NULL) {
        errno = ENOMEM;
        goto err;
    }

    /* did it fit? */
    if (strlcpy(ge->group.name, name, sz) >= sz) {
        errno = ENAMETOOLONG;
        goto err;
    }

    ge->info       = info;
    ge->group.priv = priv;

    return ge;
err:
    if (ge != NULL)
        free(ge);
    return NULL;
}

static bool
is_valid_group_name(const char *name, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        const char c = name[i];

        /* allow underscores */
        if (c == '_')
            continue;
        /* don't allow anything non-alphanumeric */
        if (!isalnum(c))
            return false;
    }
    return true;
}

const uds_group_t *
uds_create_group(const uds_info_t *_info, const char *group, void *priv)
{
    const struct uds_info *info = _info;
    const uds_group_t *ret;
    struct group_entry *ge;
    size_t len;
    int mret;

    if (group == NULL || info == NULL || group[0] == '\0') {
        errno = EINVAL;
        return NULL;
    }
    len = strnlen(group, UDS_MAX_GRP_NAME_LEN);
    if (len >= UDS_MAX_GRP_NAME_LEN) {
        errno = ENAMETOOLONG;
        return NULL;
    }
    if (!is_valid_group_name(group, len)) {
        errno = EINVAL;
        return NULL;
    }

    ge = create_group(info, group, priv);
    if (ge == NULL) {
        /* create_group sets errno */
        return NULL;
    }

    mret = pthread_rwlock_wrlock(&lck);
    if (mret != 0) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Mutex lock failed: %s\n", strerror(mret));
        errno = mret;
        free(ge);
        return NULL;
    }

    if (find_group_by_name(info, group) == NULL) {
        TAILQ_INSERT_TAIL(&group_list.list, ge, next);
        ret = &ge->group;
    } else {
        errno = EEXIST;
        ret   = NULL;
        free(ge);
    }

    mret = pthread_rwlock_unlock(&lck);
    if (mret != 0)
        snprintf(uds_log_error, sizeof(uds_log_error), "Mutex unlock failed: %s\n", strerror(mret));

    return ret;
}

int
uds_register(const uds_group_t *grp, const char *cmd, uds_cb fn)
{
    struct group_entry *ge;
    struct cmd_entry *cb;
    int mret, ret = -1; /* fail until told otherwise */

    if (cmd == NULL || cmd[0] != '/' || grp == NULL || fn == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (strnlen(cmd, UDS_MAX_CMD_LEN) >= UDS_MAX_CMD_LEN) {
        errno = ENAMETOOLONG;
        return -1;
    }

    /* lock both lists as we need them both */
    mret = pthread_rwlock_wrlock(&lck);
    if (mret != 0) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Mutex lock failed: %s\n", strerror(mret));
        errno = mret;
        goto out;
    }

    /* try to find our group first */
    ge = find_group_by_handle(grp);
    if (ge == NULL) {
        errno = ENOENT;
        goto out;
    }

    /* group found, now see if the command exists already */
    if (find_command(cmd, ge) == NULL) {
        cb = create_command(cmd, ge, fn);
        if (cb == NULL) {
            /* create_command sets errno */
            goto out;
        }
        TAILQ_INSERT_TAIL(&clb_list.list, cb, next);
        ret = 0; /* success */
    } else {
        /* command already exists */
        errno = EEXIST;
        goto out;
    }

out:
    mret = pthread_rwlock_unlock(&lck);
    if (mret != 0)
        snprintf(uds_log_error, sizeof(uds_log_error), "Mutex lock failed: %s\n", strerror(mret));
    return ret;
}

static int
list_cmd(uds_client_t *c, const char *cmd, const char *params)
{
    struct cmd_entry *cb;
    struct uds_info *info;
    bool first = true;

    CNE_SET_USED(cmd);
    CNE_SET_USED(params);

    info = c->info;

    uds_append(c, "\"/\":[");
    TAILQ_FOREACH (cb, &clb_list.list, next) {
        const struct group_entry *ge = cb->ge;
        /* skip groups for other sockets */
        if (ge->info != info)
            continue;
        /* if we had items before, append comma after the last item */
        if (!first)
            uds_append(c, ",");
        first = false;

        uds_append(c, "\"");
        /* if this is not a root group, append group name */
        if (!is_root_group(ge))
            uds_append(c, "/%s", ge->group.name);
        uds_append(c, "%s\"", cb->cmd);
    }
    uds_append(c, "]");

    return 0;
}

static int
info_cmd(uds_client_t *c, const char *cmd, const char *params)
{
    CNE_SET_USED(cmd);
    CNE_SET_USED(params);
    uds_append(c, "\"version\":\"%s\"", cne_version());
    uds_append(c, ",\"pid\":%d", getpid());
    uds_append(c, ",\"max_output_len\":%d", UDS_MAX_BUF_LEN);

    return 0;
}

static int
invalid_cmd(uds_client_t *c, const char *cmd, const char *params)
{
    if (params)
        uds_append(c, "\"error\":\"invalid cmd (%s,%s)\"", cmd, params);
    else
        uds_append(c, "\"error\":\"invalid cmd (%s)\"", cmd);

    return 0;
}

static void
perform_command(uds_cb fn, uds_client_t *c)
{
    int ret;

    uds_append(c, "{");

    ret = fn(c, c->cmd, c->params);

    if (ret == UDS_NO_OUTPUT)
        goto leave;

    uds_append(c, "}");
    if (write(c->s, c->buffer, c->used) < 0)
        perror("Error writing to socket");

    if (ret < 0)
        return;

leave:
    c->buffer[0] = '\0';
    c->used      = 0;
}

static uds_cb
get_cb_fn(struct uds_client *c, const char **cmd)
{
    const struct group_entry *ge;
    const char *cmdptr = *cmd;
    struct cmd_entry *cb;

    /* find group */
    ge = find_group_by_cmd(c->info, cmdptr);

    /* if we didn't find any matching group, this is an invalid command */
    if (ge == NULL)
        return invalid_cmd;

    /*
     * we found a matching group, now we need to match the command. for root
     * group, there is a 1:1 match of command to full path, whereas for a user
     * group, we need to cut off the first part of the path.
     */
    if (!is_root_group(ge)) {
        /* this is a user group, cut off the first part of cmd */
        cmdptr = strchr(CNE_PTR_ADD(cmdptr, 1), '/'); /* second forward slash */
    }

    cb = find_command(cmdptr, ge);
    if (cb != NULL) {
        /* we're passing this to the user, so save the group pointer */
        c->group = &ge->group;
        /* also update the command pointer */
        *cmd = cmdptr;
        return cb->fn;
    }

    /* we didn't find any matching command, this is an invalid command */
    return invalid_cmd;
}

static void *
client_handler(void *_c)
{
    uds_client_t *c = _c;
    char cbuf[UDS_MAX_CMD_LEN + 1];

    if (!c)
        return NULL;

    int ret = pthread_setname_np(pthread_self(), "uds-client-hdlr");
    if (ret) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Error Couldn't set socket name: %s\n",
                 strerror(ret));
        goto leave;
    }

    cbuf[0] = '\0';
    while (c->info->running > 0) {
        int bytes, mret;
        char cmsgbuf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr *cmsg;
        struct msghdr msg;
        struct iovec iov;
        uds_cb fn;
        char *ptr;

        iov.iov_base = cbuf;
        iov.iov_len  = sizeof(char) * UDS_MAX_CMD_LEN;

        msg.msg_name       = 0;
        msg.msg_namelen    = 0;
        msg.msg_iov        = &iov;
        msg.msg_iovlen     = 1;
        msg.msg_flags      = 0;
        msg.msg_control    = cmsgbuf;
        msg.msg_controllen = CMSG_LEN(sizeof(cmsgbuf));
        bytes              = recvmsg(c->s, &msg, 0);

        if (bytes <= 0)
            break;

        /* receive data is not null terminated */
        cbuf[bytes] = '\0';

        cmsg = CMSG_FIRSTHDR(&msg);
        if (cmsg)
            c->cmsg = cmsg;

        /* find command string */
        c->cmd     = strtok_r(cbuf, ",", &ptr);
        c->params  = strtok_r(NULL, ",", &ptr);
        c->params2 = strtok_r(NULL, ",", &ptr);

        /* read-lock the lists */
        mret = pthread_rwlock_rdlock(&lck);
        if (mret != 0) {
            snprintf(uds_log_error, sizeof(uds_log_error), "Mutex lock failed: %s\n",
                     strerror(mret));
            goto leave;
        }

        /* this also updates the c->cmd pointer to point to start of command */
        fn = get_cb_fn(c, &c->cmd);

        mret = pthread_rwlock_unlock(&lck);
        if (mret != 0)
            snprintf(uds_log_error, sizeof(uds_log_error), "Mutex unlock failed: %s\n",
                     strerror(mret));

        /* TODO: by the time we do a perform command, group and command are stale */
        perform_command(fn, c);

        cbuf[0] = '\0';
    }

leave:
    close(c->s);

    free(c->buffer);
    free(c);

    return NULL;
}

static void *
socket_listener(void *_info)
{
    uds_info_t *info = _info;
    uds_client_t *c;
    struct pollfd fds = {0};

    int ret = pthread_setname_np(pthread_self(), "uds-sock-listen");
    if (ret) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Error Couldn't set socket name: %s\n",
                 strerror(ret));
        return NULL;
    }
    info->running = 1;

    while (info->running > 0) {
        pthread_t th;
        int s;

        fds.fd      = info->sock;
        fds.events  = POLLIN;
        fds.revents = 0;

        if (poll(&fds, 1, POLL_TIMEOUT) < 0)
            break;

        if (fds.revents != POLLIN)
            continue;

        s = accept(info->sock, NULL, NULL);
        if (s < 0) {
            snprintf(uds_log_error, sizeof(uds_log_error),
                     "Error with accept, process_info thread quitting\n");
            continue;
        }

        c = calloc(1, sizeof(struct uds_client));
        if (!c) {
            snprintf(uds_log_error, sizeof(uds_log_error),
                     "Unable to allocate uds_client structure\n");
            close(s);
            break;
        }
        c->s             = s;
        c->info          = info;
        c->socket_client = 0;

        int ret = pthread_create(&th, NULL, client_handler, (void *)c);
        if (ret) {
            snprintf(uds_log_error, sizeof(uds_log_error), "Unable to start uds_client handler\n");
            break;
        }
        pthread_detach(th);
    }
    info->running = -1; /* signal the listener has stopped */

    return NULL;
}

static int
create_default_group(struct uds_info *info, bool create_cmds)
{
    struct group_entry *ge;
    struct cmd_entry *list_le = NULL, *info_le = NULL;
    int mret;

    /* write-lock the lists */
    mret = pthread_rwlock_wrlock(&lck);
    if (mret != 0) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Mutex lock failed: %s\n", strerror(mret));
        errno = mret;
        return -1;
    }

    /* root group has empty name */
    ge = create_group(info, "", NULL);
    if (ge == NULL)
        goto error;
    TAILQ_INSERT_TAIL(&group_list.list, ge, next);

    if (create_cmds) {
        list_le = create_command("/", ge, list_cmd);
        if (list_le == NULL)
            goto error;
        info_le = create_command("/info", ge, info_cmd);
        if (info_le == NULL)
            goto error;

        TAILQ_INSERT_TAIL(&clb_list.list, list_le, next);
        TAILQ_INSERT_TAIL(&clb_list.list, info_le, next);
    }

    mret = pthread_rwlock_unlock(&lck);
    if (mret != 0)
        snprintf(uds_log_error, sizeof(uds_log_error), "Mutex unlock failed: %s\n", strerror(mret));

    return 0;
error:
    if (ge != NULL)
        free(ge);
    if (list_le != NULL)
        free(list_le);
    if (info_le != NULL)
        free(info_le);

    mret = pthread_rwlock_unlock(&lck);
    if (mret != 0)
        snprintf(uds_log_error, sizeof(uds_log_error), "Mutex unlock failed: %s\n", strerror(mret));

    return -1;
}

uds_info_t *
uds_get_default(void *priv)
{
    /* TODO: this is racy, need some kind of synchronization */
    if (default_info != NULL)
        return default_info;

    default_info = uds_create(NULL, "app_socket", NULL, priv);
    /* even if it failed, errno will be set */
    return default_info;
}

uds_info_t *
uds_create(const char *runtime_dir, const char *uds_name, const char **err_str, void *priv)
{
    struct uds_info *info;
    char buff[1024];
    pthread_t th;

    if (!uds_name)
        return NULL;

    if (!runtime_dir)
        runtime_dir = UDS_DEFAULT_RUNTIME_DIR;

    info = calloc(1, sizeof(struct uds_info));
    if (!info)
        return NULL;

    /* create default group and functions */
    if (create_default_group(info, true) < 0) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Error with default group creation, %s",
                 strerror(errno));
        if (err_str)
            *err_str = uds_log_error;
        goto error;
    }

    info->priv = priv;

    info->sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (info->sock < 0) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Error with socket creation, %s",
                 strerror(errno));
        if (err_str)
            *err_str = uds_log_error;
        goto error;
    }

    info->sun.sun_family = AF_UNIX;

    char *str, *s;
    struct stat statBuf;

    snprintf(buff, sizeof(buff), "%s", runtime_dir);
    s = buff;
    while ((str = strtok(s, "/")) != NULL) {
        if (str != s) {
            str[-1] = '/';
        }
        if (stat(buff, &statBuf) == -1) {
            if (mkdir(buff, 0) < 0) {
                snprintf(uds_log_error, sizeof(uds_log_error), "couldn't create directory %s\n",
                         buff);
                goto error;
            }
        } else {
            if (!S_ISDIR(statBuf.st_mode)) {
                snprintf(uds_log_error, sizeof(uds_log_error), "couldn't create directory %s\n",
                         buff);
                goto error;
            }
        }
        s = NULL;
    }

    if (chmod(runtime_dir, 0755) < 0) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Error changing path permissions: %s\n",
                 strerror(errno));
        goto error;
    }

    snprintf(info->sun.sun_path, sizeof(info->sun.sun_path), "%s/%s.%d", runtime_dir, uds_name,
             getpid());

    if (bind(info->sock, (void *)&info->sun, sizeof(info->sun)) < 0) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Error binding socket: %s", strerror(errno));
        info->sun.sun_path[0] = 0;
        goto error;
    }

    if (listen(info->sock, 1) < 0) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Error calling listen for socket: %s",
                 strerror(errno));
        goto error;
    }

    int ret = pthread_create(&th, NULL, socket_listener, info);
    if (ret) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Error Couldn't create thread: %s\n",
                 strerror(ret));
        goto error;
    }

    return info;

error:
    uds_destroy(info);
    if (err_str)
        *err_str = uds_log_error;
    return NULL;
}

static void *
socket_client(void *_info)
{
    uds_info_t *info = _info;
    uds_client_t *c;
    struct pollfd fds = {0};

    int ret = pthread_setname_np(pthread_self(), "uds-sock-client");
    if (ret) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Error Couldn't set socket name: %s\n",
                 strerror(ret));
        return NULL;
    }
    info->running = 1;

    while (info->running > 0) {
        pthread_t th;

        fds.fd      = info->sock;
        fds.events  = POLLIN;
        fds.revents = 0;

        if (poll(&fds, 1, POLL_TIMEOUT) < 0)
            break;

        if (fds.revents != POLLIN)
            continue;

        c = calloc(1, sizeof(struct uds_client));
        if (!c)
            break;

        c->s             = info->sock;
        c->info          = info;
        c->socket_client = 1;

        int ret = pthread_create(&th, NULL, client_handler, (void *)c);
        if (ret) {
            snprintf(uds_log_error, sizeof(uds_log_error), "Error Couldn't create thread: %s\n",
                     strerror(ret));
            break;
        }
        pthread_detach(th);
    }
    info->running = -1; /* signal the listener has stopped */

    return NULL;
}

const uds_group_t *
uds_get_group_by_name(const uds_info_t *info, const char *name)
{
    const struct group_entry *ge;
    int mret;

    if (info == NULL) {
        errno = EINVAL;
        return NULL;
    }
    /* if name is NULL, we're looking for the root group */
    if (name == NULL)
        name = "";

    mret = pthread_rwlock_rdlock(&lck);
    if (mret != 0) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Mutex lock failed: %s\n", strerror(mret));
        errno = mret;
        return NULL;
    }
    ge   = find_group_by_name(info, name);
    mret = pthread_rwlock_unlock(&lck);
    if (mret != 0)
        snprintf(uds_log_error, sizeof(uds_log_error), "Mutex unlock failed: %s\n", strerror(mret));

    /* if we didn't find anything, set errno */
    if (ge == NULL) {
        errno = ENOENT;
        return NULL;
    }

    return &ge->group;
}

uds_info_t *
uds_connect(const char *uds_name, const char **err_str, void *priv)
{
    struct uds_info *info;
    struct stat stat_buf;
    pthread_t th;

    if (!uds_name)
        return NULL;

    if (stat(uds_name, &stat_buf) == -1) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Error with socket creation, %s",
                 strerror(errno));
        if (err_str)
            *err_str = uds_log_error;
        return NULL;
    }

    info = calloc(1, sizeof(struct uds_info));
    if (!info)
        return NULL;

    /* create default group and functions */
    if (create_default_group(info, false) < 0) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Error with default group creation, %s",
                 strerror(errno));
        if (err_str)
            *err_str = uds_log_error;
        goto error;
    }

    info->priv = priv;

    info->sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (info->sock < 0) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Error with socket creation, %s",
                 strerror(errno));
        goto error;
    }

    info->sun.sun_family = AF_UNIX;
    snprintf(info->sun.sun_path, sizeof(info->sun.sun_path), "%s", uds_name);

    if (connect(info->sock, (struct sockaddr *)&info->sun, sizeof(info->sun)) < 0) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Error connecting to socket: %s",
                 strerror(errno));
        info->sun.sun_path[0] = 0;
        goto error;
    }

    int ret = pthread_create(&th, NULL, socket_client, info);
    if (ret) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Error Couldn't create thread: %s\n",
                 strerror(ret));
        goto error;
    }

    return info;

error:
    uds_destroy(info);
    if (err_str)
        *err_str = uds_log_error;
    return NULL;
}

int
uds_destroy_group(const uds_group_t *group)
{
    struct group_entry *ge;
    int ret, mret;

    if (group == NULL) {
        errno = EINVAL;
        return -1;
    }

    mret = pthread_rwlock_wrlock(&lck);
    if (mret != 0) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Mutex lock failed: %s\n", strerror(mret));
        errno = mret;
        return -1;
    }

    ge = find_group_by_handle(group);
    if (ge != NULL) {
        struct cmd_entry *ce, *next_ce;

        /* free all callbacks first */
        TAILQ_FOREACH_SAFE (ce, &clb_list.list, next, next_ce) {
            if (ce->ge != ge)
                continue;
            TAILQ_REMOVE(&clb_list.list, ce, next);
            free(ce);
        }

        /* remove and deallocate group itself */
        TAILQ_REMOVE(&group_list.list, ge, next);
        free(ge);

        /* success */
        ret = 0;
    } else {
        errno = ENOENT;
        ret   = -1;
    }

    mret = pthread_rwlock_unlock(&lck);
    if (mret != 0)
        snprintf(uds_log_error, sizeof(uds_log_error), "Mutex unlock failed: %s\n", strerror(mret));

    return ret;
}

void
uds_destroy(uds_info_t *_info)
{
    struct uds_info *info = _info;
    struct group_entry *ge, *next_ge;
    struct cmd_entry *ce, *next_ce;
    int mret;

    if (!info) {
        if (default_info != NULL)
            info = default_info;
        else
            return;
    }
    if (info->running > 0) {
        info->running = 0;
        while (info->running == 0)
            usleep(250000);
    }
    /* thread is done, it's safe to lock the lists now */
    mret = pthread_rwlock_wrlock(&lck);
    if (mret != 0) {
        snprintf(uds_log_error, sizeof(uds_log_error), "Mutex lock failed: %s\n", strerror(mret));
        return;
    }

    /* destroy all groups and callbacks associated with this socket */
    TAILQ_FOREACH_SAFE (ce, &clb_list.list, next, next_ce) {
        if (ce->ge->info != info)
            continue;
        TAILQ_REMOVE(&clb_list.list, ce, next);
        free(ce);
    }
    TAILQ_FOREACH_SAFE (ge, &group_list.list, next, next_ge) {
        if (ge->info != info)
            continue;
        TAILQ_REMOVE(&group_list.list, ge, next);
        free(ge);
    }
    mret = pthread_rwlock_unlock(&lck);
    if (mret != 0)
        snprintf(uds_log_error, sizeof(uds_log_error), "Mutex unlock failed: %s\n", strerror(mret));

    if (info->sock)
        close(info->sock);

    if (info->sun.sun_path[0])
        unlink(info->sun.sun_path);

    free(info);
}

__attribute__((__format__(__printf__, 2, 0))) int
uds_append(uds_client_t *_c, const char *format, ...)
{
    struct uds_client *c = _c;
    va_list ap;
    char str[PATH_MAX];
    int ret, nbytes;

    va_start(ap, format);
    ret = vsnprintf(str, sizeof(str), format, ap);
    va_end(ap);

    /* First time just allocate some memory to use for buffer */
    if (c->buffer == NULL) {
        c->buffer = malloc(4 * UDS_EXTRA_SPACE);
        if (c->buffer == NULL) {
            printf("Buffer is NULL\n");
            return -1;
        }
        memset(c->buffer, 0, (4 * UDS_EXTRA_SPACE));
        c->buf_len = (4 * UDS_EXTRA_SPACE);
        c->used    = 0;
    }

    nbytes = (ret + c->used) + UDS_EXTRA_SPACE;

    /* Increase size of buffer if required */
    if (nbytes > c->buf_len) {

        /* Make sure the max length is capped to a max size */
        if (nbytes > UDS_MAX_BUF_LEN)
            return -1;

        /* expand the buffer space */
        char *p = realloc(c->buffer, nbytes);

        if (p == NULL)
            return -1;

        c->buffer  = p;
        c->buf_len = nbytes;
    }

    /* Add the new string data to the buffer */
    c->used = strlcat(c->buffer, str, c->buf_len);

    return 0;
}

const char *
uds_cmd(uds_client_t *_c)
{
    struct uds_client *c = _c;

    return c->cmd;
}

const char *
uds_params(uds_client_t *_c)
{
    struct uds_client *c = _c;

    return c->params;
}

CNE_INIT(uds_init)
{
    TAILQ_INIT(&group_list.list);
    TAILQ_INIT(&clb_list.list);
}
