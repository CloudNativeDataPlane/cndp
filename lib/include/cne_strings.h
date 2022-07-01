/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

/**
 * @file
 *
 * String-related utility functions
 */

#ifndef _M_STRINGS_H_
#define _M_STRINGS_H_

#include <stdio.h>        // for NULL, snprintf
#include <ctype.h>
#include <stdint.h>        // for uint8_t, UINT16_MAX, UINT8_MAX, uint32_t
#include <stdlib.h>        // for strtoul
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>        // for inet_ntop
#include <bsd/bsd.h>
#include <errno.h>             // for errno
#include <bsd/string.h>        // for strlcpy
#include <sys/socket.h>        // for AF_INET

#include <cne_common.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    STR_MAX_ARGVS  = 64,  /**< Max number of args to support */
    STR_TOKEN_SIZE = 128, /**< Token max size */
};

/**
 * Trim a set of characters like "[]" or "{}" from the start and end of string.
 *
 * @param str
 *   A null terminated string to be trimmed.
 * @param set
 *   The \p set string is a set of two character values to be removed from the
 *   \p str. Removes only one set at a time, if you have more then one set to
 *   remove then you must call the routine for each set. The \p set string must
 *   be two characters and can be any characters you
 *   want to call a set.
 * @return
 *   Pointer to the trimmed string or NULL on error
 */
static __inline__ char *
strtrimset(char *str, const char *set)
{
    if (!str || !*str || !set || (strlen(set) != 2))
        return NULL;

    /* Find the beginning set character, while trimming white space */
    while ((*str == set[0]) || isspace(*str))
        str++;

    if (*str) {
        char *p = &str[strlen(str) - 1];

        while ((p >= str) && (isspace(*p) || (*p == set[1])))
            p--;

        p[1] = '\0';
    }

    return str;
}

/**
 * Remove quotes from around a string helper routine.
 *
 * @param str
 *   String to remove the quote marks or tick marks from around a string
 * @return
 *   If quote or tick marks are removed then return &str[1] or return str.
 */
static __inline__ char *
strtrim_quotes(char *str)
{
    if (strlen(str) >= 2) {
        if (str[0] == '"')
            return strtrimset(str, "\"\"");
        else if (str[0] == '\'')
            return strtrimset(str, "''");
    }
    return str;
}

/**
 * Remove leading and trailing white space from a string.
 *
 * @param str
 *   String to be trimmed, must be null terminated
 * @return
 *   pointer to the trimmed string or NULL if \p str is Null or
 *   if string is empty then return pointer to \p str
 */
static __inline__ char *
strtrim(char *str)
{
    if (!str || !*str)
        return str;

    /* trim white space characters at the front */
    while (isspace(*str))
        str++;

    /* Make sure the string is not empty */
    if (*str) {
        char *p = &str[strlen(str) - 1];

        /* trim trailing white space characters */
        while ((p >= str) && isspace(*p))
            p--;

        p[1] = '\0';
    }
    return str;
}

/**
 * Parse a string into a argc/argv list using a set of delimiters, but does
 * not handle quoted strings within the string being parsed.
 *
 * @param str
 *   String to be tokenized and will be modified, must be null terminated
 * @param delim
 *   A null terminated list of delimiters
 * @param entries
 *   A pointer to an array to place the token pointers
 * @param maxtokens
 *   Max number of tokens to be placed in \p entries
 * @return
 *   The number of tokens in the \p entries array.
 */
static __inline__ int
cne_strtok(char *str, const char *delim, char *entries[], int maxtokens)
{
    int i = 0;
    char *saved;

    if (!str || !delim || !strlen(delim) || !entries || !maxtokens)
        return -1;
    if (!strlen(str))
        return 0;

    do {
        entries[i] = strtrim(strtok_r(str, delim, &saved));
        str        = NULL;
    } while (entries[i] && (++i < maxtokens));

    return i;
}

/**
 * Parse a string into a \p argv list using a set of delimiters, but does
 * handle quoted strings within the string being parsed
 *
 * @param str
 *   String to be tokenized and will be modified, null terminated
 * @param delim
 *   A null terminated list of delimiters
 * @param argv
 *   A pointer to an array to place the token pointers
 * @param maxtokens
 *   Max number of tokens to be placed in \p entries
 * @return
 *   The number of tokens in the \p entries array.
 */
static __inline__ int
cne_strqtok(char *str, const char *delim, char *argv[], int maxtokens)
{
    char *p, *start_of_word, *s;
    int argc                                                             = 0;
    enum { INIT, WORD, STRING_QUOTE, STRING_TICK, STRING_BRACKET } state = WORD;

    if (!str || !delim || !argv || maxtokens == 0)
        return -1;

    /* Remove white space from start and end of string */
    s = strtrim(str);

    start_of_word = s;
    for (p = s; (argc < maxtokens) && (*p != '\0'); p++) {
        int c = (unsigned char)*p;

        if (c == '\\') {
            start_of_word = ++p;
            continue;
        }

        switch (state) {
        case INIT:
            if (c == '"') {
                state         = STRING_QUOTE;
                start_of_word = p + 1;
            } else if (c == '\'') {
                state         = STRING_TICK;
                start_of_word = p + 1;
            } else if (c == '{') {
                state         = STRING_BRACKET;
                start_of_word = p + 1;
            } else if (!strchr(delim, c)) {
                state         = WORD;
                start_of_word = p;
            }
            break;

        case STRING_QUOTE:
            if (c == '"') {
                *p           = 0;
                argv[argc++] = start_of_word;
                state        = INIT;
            }
            break;

        case STRING_TICK:
            if (c == '\'') {
                *p           = 0;
                argv[argc++] = start_of_word;
                state        = INIT;
            }
            break;

        case STRING_BRACKET:
            if (c == '}') {
                *p           = 0;
                argv[argc++] = start_of_word;
                state        = INIT;
            }
            break;

        case WORD:
            if (strchr(delim, c)) {
                *p            = 0;
                argv[argc++]  = start_of_word;
                state         = INIT;
                start_of_word = p + 1;
            }
            break;

        default:
            break;
        }
    }

    if ((state != INIT) && (argc < maxtokens))
        argv[argc++] = start_of_word;

    if ((argc == 0) && (p != str))
        argv[argc++] = str;

    argv[argc] = NULL;

    return argc;
}

/**
 * Convert characters in \p str to lowercase.
 *
 * @param str
 *   String to convert to lowercase
 * @return
 *   For success lower case string, NULL on error
 */
static __inline__ char *
cne_strtolower(char *str)
{
    if (!str)
        return NULL;

    for (int i = 0; i <= (int)(strlen(str)); i++)
        str[i] = tolower(str[i]);

    return str;
}

/**
 * Convert characters in \p str to uppercase.
 *
 * @param str
 *   String to convert to uppercase
 *
 * @return
 *   For success upper case string, NULL on error
 */
static __inline__ char *
cne_strtoupper(char *str)
{
    if (!str)
        return NULL;

    for (int i = 0; i <= (int)(strlen(str)); i++)
        str[i] = toupper(str[i]);

    return str;
}

/**
 * Parse a string \p list looking for \p str using delim character.
 *
 * @param list
 *   A string list of options with delim character between them.
 * @param str
 *   String to search for in \p list
 * @param delim
 *   A character string to use as a delim values
 * @return
 *   The index in the list of option strings, -1 if not found
 */
static __inline__ int
cne_stropt(const char *list, char *str, const char *delim)
{
    char *argv[STR_MAX_ARGVS + 1], *buf;

    if (!list || !str || !delim)
        return -1;

    if ((list[0] == '%') && (list[1] == '|'))
        list += 2;

    if (!*list)
        return -1;

    size_t n = strlen(list) + 2;

    buf = (char *)alloca(n);
    if (buf) {
        snprintf(buf, n, "%s", list);

        int nb = cne_strtok(buf, delim, argv, STR_MAX_ARGVS);
        if (nb < 0)
            return -1;
        for (int i = 0; i < nb; i++)
            if (!strcmp(argv[i], str))
                return i;
    }

    return -1;
}

/**
 * The function is a wrapper around strdup() and will free the previous string
 * if the pointer is present.
 */
static __inline__ char *
cne_strdupf(char *str, char *newstr)
{
    if (str)
        free(str);
    return (newstr == NULL) ? NULL : strdup(newstr);
}

/**
 * Count the number of \p c characters in a string \p s
 *
 * @param s
 *   Null terminated string to search
 * @param c
 *   character to count
 * @return
 *   Number of times the character is in string.
 */
static __inline__ int
cne_strcnt(char *s, char c)
{
    return (s == NULL || *s == '\0') ? 0 : cne_strcnt(s + 1, c) + (*s == c);
}

#ifndef _MASK_SIZE_
#define _MASK_SIZE_
/**
 * Return the number of contiguous bits in a 32bit mask variable.
 *
 * The mask can not contain gaps between bits, must be contiguous from MSB.
 *
 * @param mask
 *   The mask variable to determine the number of bits.
 * @return
 *   The number of contiguous bit in the mask.
 */
static __inline__ int
mask_size(uint32_t mask)
{
    if (mask == 0)
        return 0;
    else if (mask == 0xFF000000)
        return 8;
    else if (mask == 0xFFFF0000)
        return 16;
    else if (mask == 0xFFFFFF00)
        return 24;
    else if (mask == 0xFFFFFFFF)
        return 32;
    else {
        int i;
        for (i = 0; i < 32; i++)
            if ((mask & (1 << (31 - i))) == 0)
                break;
        return i;
    }
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* _M_STRINGS_H_ */
