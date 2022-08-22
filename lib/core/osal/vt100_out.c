/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <stdio.h>              // for NULL
#include <string.h>             // for strlen, memset, strcpy, strncmp
#include <cne_common.h>         // for CNE_PTR_CAST, cne_countof
#include <cne_strings.h>        // for cne_strtok, strtrimset
#include <bsd/string.h>         // for strlcpy
#include <strings.h>            // for index, strncasecmp
#include <stdlib.h>             // for calloc, free

#include "cne_tty.h"          // for tty_is_color_on
#include "vt100_out.h"        // for vt_rgb_code_t, vt_attrs, vt_rgb_name_t, vt_...

static struct vt_attrs _attrs[] = VT_ATTRS;

static vt_rgb_code_t _rgb_codes[] = RGB_COLOR_CODES;
static vt_rgb_name_t _rgb_names[] = RGB_COLOR_NAMES;

static vt_rgb_code_t *
match_rgb_color(char *color)
{
    vt_rgb_name_t *n;

    for (n = &_rgb_names[0]; n->name != NULL; n++) {
        if (!strncasecmp(n->name, color, strlen(color)))
            return &_rgb_codes[n->color_id];
    }
    return &_rgb_codes[0]; /* return default codes */
}

static struct vt_attrs *
match_attr(char *attr)
{
    struct vt_attrs *a;

    for (a = &_attrs[0]; a->name != NULL; a++) {
        if (!strncasecmp(a->name, attr, strlen(attr)))
            return a;
    }
    return &_attrs[0]; /* return default codes */
}

static int
color_begin(char *p, char *e, char **cb, int len)
{
    vt_rgb_code_t *fg, *bg;
    struct vt_attrs *attr;
    char data[64], *d = data, *c;
    char *toks[4] = {0};
    vt_rgb_t r, g, b;
    int n;

    if (!tty_is_color_on())
        return -1;

    memset(data, 0, sizeof(data));

    c = *cb;
    n = (e - p) + 1;

    if (n > (int)sizeof(data))
        n = (int)sizeof(data);

    /* Grab a copy of the color string tuple and trim out [] */
    strlcpy(d, p, n);
    if (strncmp("[]", d, n) == 0)
        strcpy(d, VT_DEFAULT_NAME ":" VT_DEFAULT_NAME ":off");
    else
        d = strtrimset(d, "[]");

    /* color tuple [fg_color:bg_color:attr] */
    n = cne_strtok(d, ":", toks, cne_countof(toks));

    /* Setup some defaults for missing fields */
    if (toks[0] == NULL)
        toks[0] = CNE_PTR_CAST(VT_DEFAULT_NAME, char *);
    if (toks[1] == NULL)
        toks[1] = CNE_PTR_CAST(VT_DEFAULT_NAME, char *);
    if (toks[2] == NULL)
        toks[2] = CNE_PTR_CAST(VT_DEFAULT_NAME, char *);

    /* Get RGB color format and attr pointers */
    fg   = match_rgb_color(toks[0]);
    bg   = match_rgb_color(toks[1]);
    attr = match_attr(toks[2]);

    /* Set the attribute first */
    if (attr && attr->attr != VT_NO_ATTR) {
        n = vt_attr_str(c, len, attr->attr);
        len -= n;
        c += n;
    }

    if (bg && bg->rgb_color != COLOR_DEFAULT) {
        r = (bg->rgb_color >> 16) & 0xFF;
        g = (bg->rgb_color >> 8) & 0xFF;
        b = bg->rgb_color & 0xFF;
        n = vt_rgb_str(c, len, VT_RGB_BG, r, g, b);
        len -= n;
        c += n;
    }

    if (fg && fg->rgb_color != COLOR_DEFAULT) {
        r = (fg->rgb_color >> 16) & 0xFF;
        g = (fg->rgb_color >> 8) & 0xFF;
        b = fg->rgb_color & 0xFF;
        n = vt_rgb_str(c, len, VT_RGB_FG, r, g, b);
        len -= n;
        c += n;
    }

    n = c - *cb;

    *cb = c;

    return n;
}

int
vt_color_parse(char *buff, int len)
{
    char *cbuf, *c, *b, *e;
    int b_index = 0;

    c = index(buff, '[');
    if (!c)
        return strlen(buff);

    cbuf = calloc(len + 4, 1);
    if (!cbuf)
        return -1;

    /* Move buff into cbuf and zero buff */
    strlcpy(cbuf, buff, len);

    memset(buff, 0, len);

    /* Parse cbuf for the color tuple and fill in buff */
    for (c = cbuf, b = buff; *c != '\0' && b_index < len;) {
        if (*c != '[') {
            *b++ = *c++; /* Fill buffer with text up to '[' */
            b_index++;
            len--;
            continue;
        }

        e = index(c, ']');
        if (!e) {
            *b++ = *c++; /* ']' not found assume only a '[' in text */
            b_index++;
            len--;
            continue;
        }

        /* Convert the color into a set of vt100 codes */
        if (color_begin(c, ++e, &b, len) == 0) {
            *b++ = *c++;
            b_index++;
        } else
            c = e; /* move pointer to after closing bracket */
    }
    free(cbuf);

    return b - buff; /* True size of the string or data in buffer */
}
