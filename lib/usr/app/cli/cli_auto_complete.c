/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <cne_strings.h>        // for cne_strcnt, cne_strtok
#include <alloca.h>             // for alloca
#include <stdint.h>             // for uint32_t, uintptr_t
#include <stdlib.h>             // for NULL, qsort
#include <string.h>             // for strlen, memset, strrchr, strcmp, strncmp

#include "cli.h"              // for cli, this_cli, cli_node, is_directory, CLI_...
#include "cli_input.h"        // for cli_redisplay_line
#include "cli_auto_complete.h"
#include "cli_gapbuf.h"        // for gb_str_insert, gb_copy_to_buf, gb_data_size
#include "cli_search.h"        // for cli_node_list_with_type, cli_find_node, cli...
#include "cne_common.h"        // for CNE_MAX
#include "cne_stdio.h"         // for cne_printf

static uint32_t
_column_count(struct cli_node **nodes, uint32_t node_cnt, uint32_t *len)
{
    uint32_t i, mlen = 8, cs;

    if (!nodes || !len)
        return CLI_SCREEN_WIDTH / mlen;

    /* Calculate the column size */
    for (i = 0; i < node_cnt; i++)
        mlen = CNE_MAX(mlen, strlen(nodes[i]->name));
    mlen++; /* Make sure we have at least a space between */

    *len = mlen;
    cs   = CLI_SCREEN_WIDTH / mlen;

    return cs;
}

static int
_print_nodes(struct cli_node **nodes, uint32_t node_cnt, uint32_t dir_only, char *match,
             struct cli_node **ret, int display)
{
    struct cli_node *n;
    uint32_t i, cnt = 0, ccnt, found = 0, slen, csize = 0;

    if (!node_cnt || !nodes)
        return 0;

    ccnt = _column_count(nodes, node_cnt, &csize);

    slen = (match) ? strlen(match) : 0;

    /* display the node names */
    for (i = 0; i < node_cnt; i++) {
        n = nodes[i];

        if (dir_only && !is_directory(n))
            continue;

        if (slen && strncmp(n->name, match, slen))
            continue;

        if (display) {
            if (!cnt)
                cne_printf("\n");

            cne_printf("%-*s", csize, n->name);
            if ((++cnt % ccnt) == 0)
                cne_printf("\n");
        }
        /* Found a possible match */
        if (ret)
            *ret = n;
        found++;
    }

    /* if not nodes found cnt will be zero and no CR */
    if (display && (cnt % ccnt))
        cne_printf("\n");

    return found;
}

static int
qsort_compare(const void *p1, const void *p2)
{
    const struct cli_node *n1, *n2;

    n1 = *(const struct cli_node *const *)p1;
    n2 = *(const struct cli_node *const *)p2;

    return strcmp(n1->name, n2->name);
}

static int
complete_args(int argc, char **argv, uint32_t types)
{
    struct cli_node **nodes = NULL, *node = NULL;
    struct gapbuf *gb;
    char *match;
    uint32_t node_cnt, found = 0, dir_only = 0, slen;

    if (argc)
        match = argv[argc - 1];
    else
        match = NULL;

    gb = this_cli->gb;

    if (match) {
        uint32_t stype;
        uint32_t slashes;
        char *p;

        /* Count the number of slashes in the path */
        slashes = cne_strcnt(match, '/');

        if (slashes) {
            /* full path to command given */
            if (cli_find_node(match, &node))
                if (is_executable(node))
                    return 0;

            /* if not found get last directory in path */
            node = cli_last_dir_in_path(match);

            if ((slashes == 1) && (match && (match[0] == '/'))) {
                match++;
                dir_only++;
            }
        }

        stype = CLI_ALL_TYPE; /* search for all nodes */
        if (argc > 1)
            stype = CLI_OTHER_TYPE; /* search for non-exe nodes */

        node_cnt = cli_node_list_with_type(node, stype, (void **)&nodes);
        p        = strrchr(match, '/');
        if (p)
            match = ++p;
    } else
        node_cnt = cli_node_list_with_type(NULL, types, (void **)&nodes);

    if (node_cnt) {
        struct cli_node *mnode = NULL;

        if (node_cnt > 1)
            qsort(nodes, node_cnt, sizeof(void *), qsort_compare);

        /* Only display autocomplete selections on double tabs */
        if ((this_cli->tab_cnt % 2) == 0) {
            found             = _print_nodes(nodes, node_cnt, dir_only, match, &mnode, 1);
            this_cli->tab_cnt = 0;
        } else
            found = _print_nodes(nodes, node_cnt, dir_only, match, &mnode, 1);

        /*
         * match is a pointer to the last matched node
         * found is a flag to determine if pointer is valid
         */
        if (match && mnode && (found == 1)) { /* Found a possible match */
            struct cli_node *node = (struct cli_node *)mnode;
            char *s;
            int nlen;

            this_cli->tab_cnt = 0;

            s = strrchr(match, '/');
            if (s)
                match = ++s;

            slen = strlen(match);
            nlen = (strlen(node->name) - slen);

            if (nlen > 0) /* Add the rest of the matching command */
                gb_str_insert(gb, &node->name[slen], nlen);

            if (is_directory(node))
                gb_str_insert(gb, (char *)(uintptr_t) "/", 1);
            else
                gb_str_insert(gb, (char *)(uintptr_t) " ", 1);
        }
    }
    cli_node_list_free(nodes);

    return found;
}

void
cli_auto_complete(void)
{
    char *argv[CLI_MAX_ARGVS + 1];
    char *line;
    int argc, size, ret;

    memset(argv, '\0', sizeof(argv));

    /* Find the current command line size */
    size = gb_data_size(this_cli->gb);

    /* allocate memory for the command line */
    line = alloca(size + 1);
    if (!line)
        return;
    memset(line, '\0', size + 1);

    /* Copy the current command line into the local buffer */
    gb_copy_to_buf(this_cli->gb, line, size);

    /* tokenize the line into command and command args */
    argc = cne_strtok(line, " \r\n", argv, CLI_MAX_ARGVS);
    if (argc < 0)
        return;

    if (argc == 0) {
        ret = complete_args(argc, argv, CLI_ALL_TYPE);

        if (ret)
            cli_redisplay_line();
        return;
    }

    /* no space before cursor maybe a command completion request */
    if (gb_get_prev(this_cli->gb) != ' ') {
        ret = complete_args(argc, argv, CLI_ALL_TYPE);

        /* if we get an error then redisplay the line */
        if (ret)
            cli_redisplay_line();
    } else {
        char *save = alloca(size + 1);

        if (!save)
            return;

        memset(save, '\0', size + 1);

        /* Call function to print out help text, plus save a copy */
        gb_copy_to_buf(this_cli->gb, save, size);

        /* Add the -? to the command */
        gb_str_insert(this_cli->gb, (char *)(uintptr_t) "-?", 2);

        cli_execute();

        /* reset the input buffer to remove -? */
        gb_reset_buf(this_cli->gb);

        /* insert the saved string back to the input buffer */
        gb_str_insert(this_cli->gb, save, size);

        cli_redisplay_line();
    }
}
