/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020-2023 Intel Corporation
 */

// IWYU pragma: no_include <bits/struct_stat.h>

#include <stdio.h>             // for NULL, size_t, sscanf, EOF
#include <unistd.h>            // for close, ssize_t, read, unlink, write
#include <stdlib.h>            // for calloc, free
#include <sys/socket.h>        // for bind, PF_INET, PF_LOCAL, accept, connect
#include <sys/un.h>            // for sockaddr_un
#include <sys/stat.h>          // for chmod, stat
#include <bsd/string.h>        // for strlcpy
#include <poll.h>              // for pollfd, poll, POLLIN
#include <errno.h>             // for errno, EAGAIN, EINPROGRESS, EINTR, EWO...
#include <string.h>            // for memcpy, memset, strnlen
#include <strings.h>           // for strncasecmp
#include <netdb.h>             // for gethostbyname, hostent
#include <fcntl.h>             // for fcntl, F_SETFL, O_NONBLOCK, S_IWGRP
#include <netinet/in.h>        // for sockaddr_in, in_addr, INADDR_ANY, htons
#include <arpa/inet.h>         // for inet_aton

#include "csock_private.h"        // for c_sock_t, c_sock::(anonymous), CSOCK_U...
#include "csock.h"

#ifndef IPPORT_USERRESERVED
#define IPPORT_USERRESERVED 5000
#endif

int
csock_is_closed(csock_t *_c)
{
    c_sock_t *c = _c;

    if (!c || c->fd == -1)
        return 1;

    return 0;
}

static ssize_t
default_read(csock_t *_c, char *data, size_t len)
{
    c_sock_t *c = _c;
    ssize_t nb_bytes;

    if ((nb_bytes = read(c->fd, data, len)) < 0) {
        if (errno != EWOULDBLOCK && errno != EINTR)
            return -1;
    }

    if (nb_bytes == 0)
        c->flags |= CSOCK_EOF;

    return nb_bytes;
}

static ssize_t
default_write(csock_t *_c, char *data, size_t len)
{
    c_sock_t *c = _c;
    ssize_t nb_bytes;

    if ((c->fd < 0) || (nb_bytes = write(c->fd, data, len)) < 0)
        return -1;

    return nb_bytes;
}

static int
default_close(csock_t *_c)
{
    c_sock_t *c = _c;

    if (c && c->fd >= 0) {
        int fd = c->fd;

        c->fd = -1;
        if (close(fd) < 0)
            return -1;
    }

    return 0;
}

static int
__config(c_sock_t *c)
{
    struct sockaddr_in *sa;

    /* Test for a Unix Domain socket path string, '/' must be the first character */
    if (c->sock_addr[0] == '/') {
        struct sockaddr_un *u = &c->addr.un;

        u->sun_family = PF_LOCAL;
        strlcpy(u->sun_path, c->sock_addr, sizeof(u->sun_path));
        c->addr_len = sizeof(struct sockaddr_un);
        return 0;
    }

    c->host_name[0] = '\0';
    c->port         = -1;
    sa              = (struct sockaddr_in *)&c->addr.sa;

    if (c->sock_addr[0] != 0) {
        // clang-format off
        struct {
            const char *fmt;
            int cnt;
        } fmts[] = {
            {CSOCK_USE_STDIO, 1},
            {"%[^:]:%d", 2},
            {"%[^:]:0x%x", 2},
            {"%s", 1},
            {NULL, -1}
        };
        // clang-format on
        int i, ret = EOF;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
        for (i = 0; fmts[i].fmt; i++) {
            ret = sscanf(c->sock_addr, fmts[i].fmt, &c->host_name, &c->port);
            if (ret == fmts[i].cnt)
                break;
        }
#pragma GCC diagnostic pop

        if (fmts[i].cnt == -1)
            return -1;

        if (strnlen(c->host_name, CSOCK_MAX_HOST_NAME_LENGTH) &&
            strncasecmp(c->host_name, CSOCK_USE_STDIO, CSOCK_MAX_HOST_NAME_LENGTH)) {
            struct in_addr host_addr = {0};

            sa->sin_family = PF_INET;
            c->addr_len    = sizeof(sa[0]);
            sa->sin_port   = (c->port != -1) ? htons(c->port) : 0;
            sa->sin_addr.s_addr =
                htonl((c->flags & CSOCK_IS_SERVER) ? INADDR_LOOPBACK : INADDR_ANY);

            if (inet_aton(c->host_name, &host_addr))
                sa->sin_addr = host_addr;
            else {
                struct hostent *host = gethostbyname(c->host_name);

                if (!host)
                    return -1;

                memcpy(&sa->sin_addr.s_addr, host->h_addr_list[0], host->h_length);
            }
        } else
            c->flags |= CSOCK_STDIO_TYPE;
    }

    return 0;
}

static int64_t
search_free_port(int sock)
{
    int64_t port;

    for (port = IPPORT_USERRESERVED; port < (1 << 16); port++) {
        struct sockaddr_in a;
        int ret;

        memset(&a, 0, sizeof(a));

        a.sin_family      = PF_INET;
        a.sin_addr.s_addr = INADDR_ANY;
        a.sin_port        = htons(port);

        ret = bind(sock, (struct sockaddr *)&a, sizeof(a));
        if (ret >= 0)
            break;
    }

    return (port < (1 << 16)) ? port : -1;
}

static int
__open(c_sock_t *c)
{
    struct sockaddr_in *in;
    struct sockaddr_un *un;

    if (__config(c) < 0)
        return -1;

    if (c->flags & CSOCK_STDIO_TYPE)
        return 0;

    in = (struct sockaddr_in *)&c->addr.sa;
    un = &c->addr.un;

    c->fd = socket(in->sin_family, SOCK_STREAM, 0);
    if (c->fd < 0)
        return -1;

    if (in->sin_family == PF_INET)
        c->port = in->sin_port;

    if (c->flags & CSOCK_IS_SERVER) {
        int bind_needed = 1;

        if (in->sin_family == PF_INET) {
            if (c->port == 0) {
                /* Need to find a free local port address */
                if ((c->port = search_free_port(c->fd)) < 0)
                    return -1;
                bind_needed = 0;
            }
        } else if (in->sin_family == PF_LOCAL)
            unlink(un->sun_path);

        int v = 1;
        if (setsockopt(c->fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v)) < 0)
            return -1;

        if (bind_needed && bind(c->fd, &c->addr.sa, c->addr_len) < 0)
            return -1;

        if (listen(c->fd, 5) < 0)
            return -1;

        if (in->sin_family == PF_LOCAL && c->flags & CSOCK_GROUP_WRITE) {
            struct stat st = {0};

            if (stat(un->sun_path, &st) < 0)
                return -1;

            st.st_mode |= S_IWGRP;
            if (chmod(un->sun_path, st.st_mode) < 0)
                return -1;
        }
    } else {
        int ret;

        if ((c->flags & CSOCK_NON_BLOCKING) && fcntl(c->fd, F_SETFL, O_NONBLOCK) < 0)
            return -1;

        do {
            ret = connect(c->fd, (struct sockaddr *)in, c->addr_len);
        } while ((ret < 0) && (errno == EAGAIN));

        if ((ret < 0) && !((c->flags & CSOCK_NON_BLOCKING) && (errno == EINPROGRESS)))
            return -1;
    }

    return 0;
}

csock_t *
csock_create(csock_cfg_t *cfg)
{
    c_sock_t *c = NULL;

    if (cfg) {
        c = calloc(1, sizeof(c_sock_t));
        if (c) {
            c->fd        = -1;
            c->port      = -1;
            c->flags     = cfg->flags;
            c->client_fn = cfg->client_fn;

            strlcpy(c->sock_addr,
                    (!cfg->host_addr || cfg->host_addr[0] == '\0') ? CSOCK_USE_STDIO
                                                                   : cfg->host_addr,
                    sizeof(c->sock_addr));

            c->read_fn  = !cfg->read_fn ? default_read : cfg->read_fn;
            c->write_fn = !cfg->write_fn ? default_write : cfg->write_fn;
            c->close_fn = !cfg->close_fn ? default_close : cfg->close_fn;

            if (__open(c) < 0) {
                csock_destroy((csock_t *)c);
                c = NULL;
            }
        }
    }

    return (csock_t *)c;
}

void
csock_destroy(csock_t *_c)
{
    c_sock_t *c = _c;

    if (c) {
        if (c->fd != -1)
            close(c->fd);
        free(c);
    }
}

csock_t *
csock_accept(csock_t *_s)
{
    c_sock_t *s = _s;
    c_sock_t *c = NULL;

    if (s) {
        csock_cfg_t cfg = {0};
        socklen_t len;

        /* Create the new csock_t structure with some default values */
        cfg.flags     = s->flags;
        cfg.client_fn = s->client_fn;
        cfg.read_fn   = s->read_fn;
        cfg.write_fn  = s->write_fn;
        cfg.close_fn  = s->close_fn;

        if ((c = csock_create(&cfg)) == NULL)
            return NULL;

        /* Accept the new connection and add the fd to the new csock_t structure */
        if ((c->fd = accept(s->fd, 0, 0)) < 0)
            goto err_exit;

        /* Set the new socket to be non-blocking. */
        if (fcntl(c->fd, F_SETFL, O_NONBLOCK) < 0)
            goto err_exit;

        /* Get peer info. */
        len = sizeof(s->peer);
        if (getpeername(c->fd, &s->peer, &len) < 0)
            goto err_exit;

        c->flags = CSOCK_IS_CLIENT; /* The connection is established and is a client connection */
    }
    return c;

err_exit:
    csock_destroy(c);
    return NULL;
}

static void *
__listener(void *_c)
{
    c_sock_t *c = _c;
    csock_t *nc;
    struct pollfd fds = {0};

    while (!csock_is_closed(c)) {
        fds.fd      = csock_get_fd(c);
        fds.events  = POLLIN;
        fds.revents = 0;

        if (poll(&fds, 1, 64) < 0)
            break;

        if (fds.revents == POLLIN) {
            void *retval;

            nc = csock_accept(c);
            if (!nc)
                continue;

            retval = c->client_fn(nc);
            if (retval == (void *)1)
                return retval;
        }
    }
    csock_close(c);

    return NULL;
}

int
csock_server_start(csock_t *_c)
{
    c_sock_t *c  = _c;
    void *retval = NULL;

    if (!c)
        return -1;

    /* when we are using stdin/stdout, just call the client function */
    if (c->flags & CSOCK_STDIO_TYPE)
        return (c->client_fn(_c) == NULL) ? 0 : -1;
    else
        retval = __listener(_c);

    return (retval == NULL) ? 0 : 1;
}

ssize_t
csock_read(csock_t *_c, char *data, size_t len)
{
    c_sock_t *c = _c;

    if (!c)
        return -1;
    if (len == 0 || csock_eof(_c))
        return 0;

    return c->read_fn(_c, data, len);
}

ssize_t
csock_write(csock_t *_c, char *data, size_t len)
{
    c_sock_t *c = _c;

    if (!c)
        return -1;
    if (len == 0 || csock_eof(c))
        return 0;

    return c->write_fn(_c, data, len);
}

int
csock_close(csock_t *_c)
{
    c_sock_t *c = _c;

    if (!c)
        return -1;
    if (c->fd < 0)
        return 0;

    return c->close_fn(_c);
}

int
csock_eof(csock_t *_c)
{
    c_sock_t *c = _c;

    return (c->flags & CSOCK_EOF);
}

int
csock_get_fd(csock_t *_c)
{
    c_sock_t *c = _c;

    if (!c)
        return -1;

    return c->fd;
}

int
csock_set_fd(csock_t *_c, int s)
{
    c_sock_t *c = _c;

    if (!c || s < 0)
        return -1;

    c->fd = s;

    return 0;
}

struct sockaddr *
csock_get_peer(csock_t *_c)
{
    c_sock_t *c = _c;

    return (c) ? &c->peer : NULL;
}
