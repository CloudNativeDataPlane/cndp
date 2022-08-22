/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <cne_strings.h>        // for cne_strtok, cne_stropt
#include <alloca.h>             // for alloca
#include <ctype.h>              // for isdigit, isxdigit, isprint
#include <stdio.h>              // for NULL, snprintf
#include <string.h>             // for memset, strcmp, strcpy, strchr, strlen
#include <bsd/string.h>         // for strlcpy
// IWYU pragma: no_include <cli_map.h>

#include "cli.h"              // for CLI_MAX_ARGVS, CLI_MAX_PATH_LENGTH
#include "cli_map.h"          // for cli_map, cli_map_dump, cli_map_list_search
#include "cne_stdio.h"        // for cne_printf

int
cli_map_list_search(const char *fmt, char *item, int index)
{
    char *buf;
    int size;
    char *opts[CLI_MAX_ARGVS + 1];

    size = strlen(fmt) + 1;
    buf  = alloca(size);
    if (!buf)
        return -1;

    memset(buf, '\0', size);
    memset(opts, '\0', sizeof(opts));

    snprintf(buf, size, "%s", fmt);
    cne_strtok(buf, " ", opts, CLI_MAX_ARGVS);

    /* Skip the %| in the string options */
    return cne_stropt(&opts[index][2], item, "|");
}

static int
is_map_valid(const char *fmt, char *arg)
{
    int ret = 0;

    if (strchr("%bdDhHsn46mkPC|l", fmt[1]) == NULL)
        return ret;

    /* validate all of the characters matching the format */
    do {
        ret = 0;
        switch (fmt[1]) {
        case '%':
            ret = 1;
            break;
        case 'b':
            if (isdigit(*arg))
                ret = 1;
            break;
        case 'd':
            if (isdigit(*arg))
                ret = 1;
            break;
        case 'D':
            if (isdigit(*arg))
                ret = 1;
            break;
        case 'h':
            if (isxdigit(*arg))
                ret = 1;
            break;
        case 'H':
            if (isxdigit(*arg))
                ret = 1;
            break;
        case 's':
            if (isprint(*arg))
                ret = 1;
            break;
        /* TODO: validate this is a valid IPv4 network address */
        case 'n':
            if (isdigit(*arg))
                ret = 1;
            break;
        /* TODO: validate this is a valid IPv4 address */
        case '4':
            if (isdigit(*arg))
                ret = 1;
            break;
        /* TODO: validate this is a valid IPv6 address */
        case '6':
            if (isdigit(*arg))
                ret = 1;
            break;
        /* TODO: validate this is a valid MAC address */
        case 'm':
            if (isxdigit(*arg))
                ret = 1;
            break;
        case 'k':
            return 1;
        /* list of lports or cores or the word all */
        case 'P':
            if (isdigit(*arg) || (*arg == 'a'))
                ret = 1;
            break;
        case 'C':
            if (isdigit(*arg) || (*arg == 'a'))
                ret = 1;
            break;
        case '|':
            return (cne_stropt(&fmt[1], arg, "|") == -1) ? 0 : 1;
        case 'l':
            ret = 1;
            break;
        default:
            return 0;
        }
        arg++;
    } while (*arg && (ret == 0));

    return ret;
}

struct cli_map *
cli_mapping(struct cli_map *maps, int argc, char **argv)
{
    int nb_args, i, j, ok;
    const char *m;
    char line[CLI_MAX_PATH_LENGTH + 1], *map[CLI_MAX_ARGVS], *p;

    memset(line, '\0', sizeof(line));
    memset(map, '\0', sizeof(map));

    p = line;
    for (i = 0; (m = maps[i].fmt) != NULL; i++) {
        strcpy(p, m);

        nb_args = cne_strtok(p, " ", map, CLI_MAX_ARGVS);

        /* display the cli MAP if present as some help */
        if (!strcmp("-?", argv[argc - 1]) || !strcmp("?", argv[argc - 1])) {
            cli_maps_show(maps, argc, argv);
            return NULL;
        }

        if (nb_args != argc)
            continue;

        /* Scan the map entry looking for a valid match */
        for (j = 0, ok = 1; ok && (j < argc); j++) {
            if (map[j][0] == '%') {
                /* Found a format '%' validate it */
                if (!is_map_valid(map[j], argv[j]))
                    ok = 0;
                /* a constant string match valid */
            } else if (strcmp(map[j], argv[j]))
                ok = 0;
        }

        if (ok)
            return &maps[i];
    }

    return NULL;
}

static void
decode_map(const char *fmt)
{
    char *argv[CLI_MAX_ARGVS + 1];
    char line[CLI_MAX_PATH_LENGTH + 1];
    int n, i;

    memset(argv, '\0', sizeof(argv));

    strlcpy(line, fmt, sizeof(line));
    if (fmt[0] != '%') {
        cne_printf("%s ", fmt);
        return;
    }

    switch (fmt[1]) {
    case '%':
        cne_printf("%% ");
        break;
    case 'b':
        cne_printf("<8bit number> ");
        break;
    case 'd':
        cne_printf("<32bit number> ");
        break;
    case 'D':
        cne_printf("<64bit number> ");
        break;
    case 'h':
        cne_printf("<32bit hex> ");
        break;
    case 'H':
        cne_printf("<64bit hex> ");
        break;
    case 's':
        cne_printf("<string> ");
        break;
    case '4':
        cne_printf("<IPv4 Address> ");
        break;
    case '6':
        cne_printf("<IPv6 Address> ");
        break;
    case 'm':
        cne_printf("<MAC address> ");
        break;
    case 'k':
        cne_printf("<kvargs> ");
        break;
    case 'P':
        cne_printf("<portlist> ");
        break;
    case 'C':
        cne_printf("<corelist> ");
        break;
    case '|':
        cne_printf("[");
        n = cne_strtok(&line[2], "|", argv, CLI_MAX_ARGVS);
        for (i = 0; i < n; i++)
            cne_printf("%s%s", argv[i], (i < (n - 1)) ? "|" : "");
        cne_printf("] ");
        break;
    case 'l':
        cne_printf("<list> ");
        break;
    default:
        cne_printf("<unknown> ");
        break;
    }
}

void
cli_map_show(struct cli_map *m)
{
    int i, nb_args;
    char line[CLI_MAX_PATH_LENGTH + 1], *map[CLI_MAX_ARGVS + 1], *p;

    memset(line, '\0', sizeof(line));
    memset(map, '\0', sizeof(map));

    p = line;

    strcpy(p, m->fmt);

    nb_args = cne_strtok(p, " ", map, CLI_MAX_ARGVS);

    if (map[0])
        cne_printf("  %s ", map[0]);
    for (i = 1; i < nb_args; i++)
        decode_map(map[i]);
    cne_printf("\n");
}

void
cli_maps_show(struct cli_map *maps, int argc, char **argv)
{
    struct cli_map *m;
    char line[CLI_MAX_PATH_LENGTH + 1], *map[CLI_MAX_ARGVS + 1];
    int nb_args;

    if (!argc)
        return;

    cne_printf("\nUsage:\n");
    for (m = maps; m->fmt != NULL; m++) {
        line[0] = '\0';
        map[0]  = NULL;

        strlcpy(line, m->fmt, sizeof(line));

        nb_args = cne_strtok(line, " ", map, CLI_MAX_ARGVS);

        if (nb_args && !strcmp(argv[0], map[0]))
            cli_map_show(m);
    }
}

void
cli_map_dump(struct cli_map *maps, int argc, char **argv)
{
    int i, nb_args;
    struct cli_map *m;
    char line[CLI_MAX_PATH_LENGTH + 1], *map[CLI_MAX_ARGVS + 1], *p;

    memset(line, '\0', sizeof(line));
    memset(map, '\0', sizeof(map));

    p = line;

    m = cli_mapping(maps, argc, argv);
    if (!m) {
        cne_printf("Map for %d/", argc);
        for (i = 0; i < argc; i++) {
            cne_printf("<%s>", argv[i]);
            if ((i + 1) < argc)
                cne_printf(",");
        }
        cne_printf("\n");
        return;
    }

    if (m->fmt) {
        strlcpy(p, m->fmt, sizeof(line));

        nb_args = cne_strtok(p, " ", map, CLI_MAX_ARGVS);

        if (map[0])
            cne_printf("%4d - %s == %s\n", m->index, argv[0], map[0]);
        for (i = 1; i < argc && i < nb_args; i++)
            cne_printf("       %s == %s\n", argv[i], map[i]);
    }
}
