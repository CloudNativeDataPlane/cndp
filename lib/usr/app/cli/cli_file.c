/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <cli_file.h>
#include <alloca.h>        // for alloca
#include <libgen.h>        // for basename
#include <stdio.h>         // for NULL, size_t, fread, pclose, popen, FILE
#include <stdlib.h>        // for abs, free, realloc, malloc
#include <string.h>        // for strchr, memcpy, strlen, strcpy

#include "cli.h"               // for cli_node, is_file, cli_node::(anonymous)
#include "cli_file.h"          // for is_data_rdonly, is_file_wr, is_seek_cur, is_...
#include "cli_search.h"        // for cli_find_node, cli_last_dir_in_path
#include "cne_common.h"        // for CNE_MIN
#include "cne_tty.h"           // for tty_write

struct cli_node *
cli_file_open(const char *path, const char *type)
{
    struct cli_node *node;
    uint32_t flags = 0;

    if (!path)
        return NULL;

    if (!cli_find_node(path, &node))
        return NULL;

    if (!is_file(node))
        return NULL;

    if (type && strlen(type)) {
        if (strchr(type, 'r'))
            file_set(flags, CLI_FILE_RD);
        if (strchr(type, 'w'))
            file_set(flags, CLI_FILE_WR);
        if (strchr(type, '+'))
            file_set(flags, CLI_FILE_APPEND);
    } else
        file_set(flags, CLI_FILE_RD);

    file_set(flags, CLI_FILE_OPEN);

    if (node->ffunc(node, NULL, 0, flags))
        return NULL;

    return node;
}

int
cli_file_close(struct cli_node *node)
{
    uint32_t flags = CLI_FILE_CLOSE;

    if (!node)
        return -1;
    return node->ffunc(node, NULL, 0, flags);
}

int
cli_file_read(struct cli_node *node, char *buff, int len)
{
    uint32_t flags = CLI_FILE_RD;

    if (!node || !is_file(node))
        return -1;
    return node->ffunc(node, buff, len, flags);
}

int
cli_file_write(struct cli_node *node, char *buff, int len)
{
    uint32_t flags = CLI_FILE_WR;

    if (!node || !is_file(node))
        return -1;
    if (is_data_rdonly(node->fflags))
        return -1;
    return node->ffunc(node, buff, len, flags);
}

int
cli_file_seek(struct cli_node *node, int offset, uint32_t whence)
{
    if (!node || !is_file(node))
        return -1;

    switch (whence) {
    case CLI_SEEK_SET:
    case CLI_SEEK_CUR:
    case CLI_SEEK_END:
        break;
    default:
        return -1;
    }
    return node->ffunc(node, NULL, offset, whence);
}

int
cli_readline(struct cli_node *node, char *buff, int len)
{
    int i, n;
    char c;

    if (!node || !buff || !is_file(node))
        return -1;
    /* Needs to be optimized for performance ??? */
    for (i = 0, c = '\0'; i < len && c != '\n'; i++) {
        n = cli_file_read(node, &c, 1);
        if (n <= 0)
            break;
        buff[i] = c;
    }
    buff[i] = '\0';
    return i;
}

/* Add generic function for handling files */
int
cli_file_handler(struct cli_node *node, char *buff, int len, uint32_t opt)
{
    char *p;

    if (!node || !is_file(node))
        return -1;

    if (opt & (CLI_SEEK_SET | CLI_SEEK_CUR | CLI_SEEK_END)) {
        size_t saved = node->foffset;

        if (is_seek_set(opt)) {
            if (len < 0)
                return -1;
            node->foffset = len;
        } else if (is_seek_cur(opt)) {
            if (len < 0) {
                len = abs(len);
                if ((size_t)len > node->file_size)
                    node->foffset = 0;
                else
                    node->foffset -= len;
            } else
                node->foffset += len;
        } else if (is_seek_end(opt)) {
            if (len < 0) {
                len = abs(len);
                if ((size_t)len > node->file_size)
                    node->foffset = 0;
                else
                    node->foffset = node->file_size - len;
            } else
                node->foffset = node->file_size + len;
        }

        if (node->foffset > node->file_size) {
            if (!(node->fflags & CLI_FILE_APPEND)) {
                node->foffset = saved;
                if (node->fflags & (CLI_FREE_DATA | CLI_DATA_EXPAND)) {
                    char *data;
                    data = realloc(node->file_data, node->foffset);
                    if (!data)
                        return -1;
                    node->file_data = data;
                    node->file_size = node->foffset;
                } else /* TODO: add code to expand the file */
                    return -1;
            } else {
                node->foffset = saved;
                return -1;
            }
        }
    } else if (is_seek_cur(opt))
        node->foffset += len;
    else if (is_seek_end(opt))
        node->foffset += len;
    else if (is_file_close(opt)) {
        if (node->file_data && (node->fflags & CLI_FREE_DATA)) {
            free(node->file_data);
            node->file_data = NULL;
            node->file_size = 0;
        }
        node->foffset = 0;
    } else if (is_file_open(opt)) {
        if (is_file_append(opt)) {
            node->fflags |= CLI_FILE_APPEND;
            node->foffset = node->file_size;
        }
        if (is_file_wr(opt))
            node->fflags |= CLI_FILE_WR;
    } else if (is_file_rd(opt)) {
        if (len <= 0)
            return 0;

        len = CNE_MIN(len, (int)(node->file_size - node->foffset));

        p = node->file_data + node->foffset;

        memcpy(buff, p, len);

        node->foffset += len;
    } else if (is_file_wr(opt)) {
        if (!is_data_rdonly(node->fflags))
            return -1;
        if (len <= 0)
            return 0;
        if ((node->foffset + len) < node->file_size) {
            p = node->file_data + node->foffset;
            memcpy(p, buff, len);
            node->foffset += len;
        } else {
            p               = realloc(node->file_data, (node->foffset + len));
            node->file_data = p;
            node->file_size = node->foffset + len;
            node->foffset += len;
        }
    }

    return len;
}

struct cli_node *
cli_file_create(const char *path, const char *type)
{
    struct cli_node *node, *parent;
    char *file, *mypath;
    char *data = NULL;

    node = cli_file_open(path, type);
    if (node)
        return node;

    mypath = alloca(strlen(path) + 1);

    strcpy(mypath, path);

    file = basename(mypath);

    data = malloc(CLI_FILE_SIZE);
    if (data) {
        parent = cli_last_dir_in_path(path);
        if (parent) {
            node = cli_add_file(file, parent, cli_file_handler, "");
            if (node) {
                node->file_data = data;
                node->file_size = CLI_FILE_SIZE;
                node->fflags    = CLI_FREE_DATA;
                if (strchr(type, 'r') && !strchr(type, 'w'))
                    node->fflags |= CLI_DATA_RDONLY;
                node->foffset = 0;
                node->fflags  = 0;
                node->fstate  = 0;
                return node;
            }
        }
    }

    free(data);
    return NULL;
}

int
cli_system(char *p)
{
    char buf[256];
    size_t n, tot = 0;
    FILE *f;

    f = popen(p, "r");
    if (!f)
        return -1;

    while ((n = fread(buf, 1, sizeof(buf) - 1, f)) > 0) {
        /* always add null-terminator in case fread does not */
        buf[n] = '\0';
        tty_write(buf, n);
        tot += n;
    }

    pclose(f);

    return tot;
}
