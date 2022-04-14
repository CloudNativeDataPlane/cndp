/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

/*
 jsonc2json a tool to help validate and convert json-c files.
*/

// IWYU pragma: no_include <bits/getopt_core.h>

#include <fcntl.h>                      // for open, O_RDONLY
#include <getopt.h>                     // for no_argument, getopt_long, option
#include <stdio.h>                      // for printf, fprintf, NULL, stderr, size_t
#include <stdlib.h>                     // for free, exit, realloc, EXIT_SUCCESS
#include <string.h>                     // for memcpy, strcmp, strlen
#include <unistd.h>                     // for close, read
#include <json-c/json_object.h>         // for json_object_to_json_string, json_ob...
#include <json-c/json_tokener.h>        // for json_tokener_free, json_tokener

#define DEFAULT_CHUNK_SIZE 1024

static int no_pretty   = 0; /* No pretty print of json text */
static int no_print    = 0; /* Do not print and text just validate */
static int strict_json = 0; /* Only parse strict JSON text not JSON-C */

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

static int
parse_jsonc(char *str)
{
    struct json_object *obj;
    json_tokener *tok;
    size_t start_pos, end_pos;

    if (!str || *str == '\0')
        return -1;

    tok = json_tokener_new_ex(JSON_TOKENER_DEFAULT_DEPTH);
    if (!tok) {
        fprintf(stderr, "Unable to create tokener instance\n");
        return -1;
    }
    json_tokener_set_flags(tok, (strict_json) ? strict_flags : 0);

    end_pos   = strlen(str);
    start_pos = 0;

    while (start_pos != end_pos) {
        obj = json_tokener_parse_ex(tok, &str[start_pos], end_pos - start_pos);
        enum json_tokener_error jerr = json_tokener_get_error(tok);
        int parse_end                = json_tokener_get_parse_end(tok);

        if (!obj && jerr != json_tokener_continue) {
            char *aterr = &str[start_pos + parse_end];
            int offset  = start_pos + parse_end;

            fflush(stdout);
            fprintf(stderr, "Failed at offset %d: %s\n  %.64s\n", offset,
                    json_tokener_error_desc(jerr), aterr);
            json_tokener_free(tok);
            return -1;
        } else {
            if (no_print == 0) {
                const char *out;

                if (no_pretty)
                    out = json_object_to_json_string(obj);
                else
                    out = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PRETTY);
                printf("%s\n", out);
            }
            start_pos += json_tokener_get_parse_end(tok);
        }
    }
    json_tokener_free(tok);

    return 0;
}

static char *
load_file(const char *filename)
{
    char *str = NULL;
    char buf[DEFAULT_CHUNK_SIZE];
    size_t len = 0, tot = 0;
    int fd, n;

    if (!strcmp("-", filename))
        fd = fileno(stdin);
    else
        fd = open(filename, O_RDONLY, 0);
    if (fd < 0)
        return str;

    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if ((len + n) >= tot) {
            tot += DEFAULT_CHUNK_SIZE;
            str = (char *)realloc(str, tot);
            if (!str)
                goto leave;
        }
        memcpy(&str[len], buf, n);
        len += n;
        str[len] = '\0';
    }
leave:
    close(fd);

    return str;
}

static void
usage(int err)
{
    printf("jsonc2json: convert file(s) from JSON-C to JSON format\n");
    printf("  Options:\n");
    printf("    -p,--no-pretty   - Disable pretty printing of the json text\n");
    printf("    -n,--no-output   - Produce no text output only verify JSON-C or JSON file(s)\n");
    printf("    -s,--strict-json - Restrict input file to JSON only text\n");
    printf("    -h,--help        - This help message\n");
    exit(err);
}

int
main(int argc, char **argv)
{
    // clang-format off
    struct option lgopts[] = {
        { "help",        no_argument, NULL, 'h' },
        { "no-pretty",   no_argument, NULL, 'p' },
        { "no-output",   no_argument, NULL, 'n' },
        { "strict-json", no_argument, NULL, 's' },
        { NULL, 0, 0, 0 }
    };
    // clang-format on
    int option_index = 0;
    char *str;
    int opt;

    while ((opt = getopt_long(argc, argv, "pnsh", lgopts, &option_index)) != -1) {
        switch (opt) {
        case 'p':
            no_pretty = 1;
            break;
        case 'n':
            no_print = 1;
            break;
        case 's':
            strict_json = 1;
            break;
        case 'h':
            usage(EXIT_SUCCESS);
            break;
        default:
            break;
        }
    }

    /* Handle the pipe case when sending json-c or json file via stdin */
    if (optind >= argc) {
        str = load_file("-");
        if (!str)
            fprintf(stderr, "Unable to read stdin\n");
        else {
            if (parse_jsonc(str) < 0)
                fprintf(stderr, "failed to parse json-c or json data\n");

            free(str);
        }
    } else {
        /* Loop on all of the files on the command line */
        for (int i = optind; i < argc && argv[i]; i++) {
            str = load_file(argv[i]);
            if (!str)
                fprintf(stderr, "Unable to open file (%s)\n", argv[i]);
            else {
                if (parse_jsonc(str) < 0)
                    fprintf(stderr, "failed to parse json-c or json text\n");

                free(str);
            }
        }
    }

    return 0;
}
