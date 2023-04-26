/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2023 Intel Corporation
 */

#include <stdio.h>           // for fflush, vprintf, NULL, stdout
#include <execinfo.h>        // for backtrace, backtrace_symbols
#include <stdarg.h>          // for va_list, va_end, va_start
#include <stdlib.h>          // for abort, exit, free
#include <cne_log.h>
#include <cne_strings.h>

#include "cne_stdio.h"        // for cne_printf, cne_snprintf
#include "cne_tty.h"          // for tty_vprintf

#define MAX_LOG_BUF_SIZE 1024 /** The max size of internal buffers */

static uint32_t cne_loglevel = CNE_LOG_INFO;

/* Set global log level */
void
cne_log_set_level(uint32_t level)
{
    if (level < CNE_LOG_EMERG)
        cne_loglevel = CNE_LOG_EMERG;
    else if (level > CNE_LOG_DEBUG)
        cne_loglevel = CNE_LOG_DEBUG;
    else
        cne_loglevel = level;
}

int
cne_log_set_level_str(char *log_level)
{
    if (!log_level)
        goto out;

#define _(n, uc, lc)                                             \
    if (!strcmp((const char *)cne_strtoupper(log_level), #uc)) { \
        int _lvl = CNE_LOG_##uc;                                 \
        cne_log_set_level(_lvl);                                 \
        return 0;                                                \
    }
    foreach_cndp_log_level;
#undef _

out:
    return 1;
}

/* Get global log level */
uint32_t
cne_log_get_level(void)
{
    return cne_loglevel;
}

/*
 * Generates a log message.
 */
int
cne_vlog(uint32_t level, const char *func, int line, const char *format, va_list ap)
{
    char buff[MAX_LOG_BUF_SIZE + 1];
    int n = 0;

    if (level > cne_loglevel)
        return 0;

    if (level <= CNE_LOG_ERR)
        n = cne_snprintf(buff, MAX_LOG_BUF_SIZE, "([red]%-24s[]:[green]%4d[]) %s", func, line,
                         format);
    else
        n = cne_snprintf(buff, MAX_LOG_BUF_SIZE, "([yellow]%-24s[]:[green]%4d[]) %s", func, line,
                         format);
    if (n <= 0)
        return n;

    buff[n] = '\0';
    /* GCC allows the non-literal "buff" argument whereas clang does not */
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif /* __clang__ */
    return vprintf(buff, ap);
#ifdef __clang__
#pragma clang diagnostic pop
#endif /* __clang__ */
}

/*
 * Generates a log message.
 */
int
cne_log(uint32_t level, const char *func, int line, const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = cne_vlog(level, func, line, format, ap);
    va_end(ap);

    return ret;
}

/*
 * Generates a log message regardless of log level.
 */
int
cne_print(const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = tty_vprintf(format, ap);
    va_end(ap);

    return ret;
}

#define BACKTRACE_SIZE 256

/* dump the stack of the calling core */
void
cne_dump_stack(void)
{
    void *func[BACKTRACE_SIZE];
    char **symb = NULL;
    int size;

    size = backtrace(func, BACKTRACE_SIZE);
    symb = backtrace_symbols(func, size);

    if (symb == NULL)
        return;

    cne_printf("[yellow]Stack Frames[]\n");
    while (size > 0) {
        cne_printf("  [cyan]%d[]: [green]%s[]\n", size, symb[size - 1]);
        size--;
    }
    fflush(stdout);

    free(symb);
}

/* call abort(), it will generate a coredump if enabled */
void
__cne_panic(const char *funcname, int line, const char *format, ...)
{
    va_list ap;

    cne_printf("[yellow]*** [red]PANIC[]:\n");
    va_start(ap, format);
    cne_vlog(CNE_LOG_CRIT, funcname, line, format, ap);
    va_end(ap);

    cne_dump_stack();
    abort();
}

/*
 * Like cne_panic this terminates the application. However, no traceback is
 * provided and no core-dump is generated.
 */
void
__cne_exit(const char *func, int line, const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    cne_vlog(CNE_LOG_CRIT, func, line, format, ap);
    va_end(ap);

    exit(-1);
}
