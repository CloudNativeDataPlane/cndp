/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <stdio.h>         // for vsnprintf, FILE
#include <stdint.h>        // for int16_t
#include <stdarg.h>        // for va_list, va_end, va_start
#include <errno.h>         // for ENOMEM
#include <stdlib.h>        // for calloc, free

#include "cne_tty.h"        // for tty_write, tty_fwrite
#include "cne_stdio.h"
#include "vt100_out.h"        // for vt_pos, vt_center_col, vt_color_parse

#define OUTPUT_BUFF_SIZE 2048

int
cne_vsnprintf(char *buff, int len, const char *fmt, va_list ap)
{
    if (vsnprintf(buff, len, fmt, ap) < 0)
        return -1;

    return vt_color_parse(buff, len);
}

int
cne_snprintf(char *buff, int len, const char *fmt, ...)
{
    va_list vaList;
    int ret;

    va_start(vaList, fmt);
    ret = cne_vsnprintf(buff, len, fmt, vaList);
    va_end(vaList);

    return ret;
}

int
cne_printf(const char *fmt, ...)
{
    char *buff;
    va_list vaList;
    int ret;

    buff = calloc(1, OUTPUT_BUFF_SIZE);
    if (!buff)
        return -ENOMEM;

    va_start(vaList, fmt);
    ret = cne_vsnprintf(buff, OUTPUT_BUFF_SIZE, fmt, vaList);
    va_end(vaList);

    ret = tty_write(buff, ret);

    free(buff);
    return ret;
}

int
cne_vprintf(const char *fmt, va_list ap)
{
    char *buff;
    int ret;

    buff = calloc(1, OUTPUT_BUFF_SIZE);
    if (!buff)
        return -ENOMEM;

    ret = cne_vsnprintf(buff, OUTPUT_BUFF_SIZE, fmt, ap);

    if (ret > 0)
        ret = tty_write(buff, ret);

    free(buff);
    return ret;
}

int
cne_printf_pos(int16_t r, int16_t c, const char *fmt, ...)
{
    char *buff;
    va_list vaList;
    int ret;

    buff = calloc(1, OUTPUT_BUFF_SIZE);
    if (!buff)
        return -ENOMEM;

    va_start(vaList, fmt);
    ret = cne_vsnprintf(buff, OUTPUT_BUFF_SIZE, fmt, vaList);
    va_end(vaList);

    if (r >= 0 && c >= 0)
        vt_pos(r, c);

    ret = tty_write(buff, ret);

    free(buff);
    return ret;
}

int
cne_fprintf(FILE *f, const char *fmt, ...)
{
    char *buff;
    va_list vaList;
    int ret;

    if (!f)
        return -1;

    buff = calloc(1, OUTPUT_BUFF_SIZE);
    if (!buff)
        return -ENOMEM;

    va_start(vaList, fmt);
    ret = cne_vsnprintf(buff, OUTPUT_BUFF_SIZE, fmt, vaList);
    va_end(vaList);

    ret = tty_fwrite(f, buff, ret);

    free(buff);
    return ret;
}

int
cne_cprintf(int16_t r, int16_t ncols, const char *fmt, ...)
{
    char *str;
    va_list vaList;
    int ret;

    str = calloc(1, OUTPUT_BUFF_SIZE);
    if (!str)
        return -ENOMEM;

    va_start(vaList, fmt);
    ret = cne_vsnprintf(str, OUTPUT_BUFF_SIZE, fmt, vaList);
    va_end(vaList);

    vt_pos(r, vt_center_col(ncols, str));

    ret = tty_write(str, ret);

    free(str);

    return ret;
}
