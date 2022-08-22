/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

// IWYU pragma: no_include <bits/termios-c_lflag.h>
// IWYU pragma: no_include <bits/termios-tcflow.h>
// IWYU pragma: no_include <bits/termios-struct.h>
// IWYU pragma: no_include <bits/termios-c_cc.h>

#include <stdio.h>            // for fprintf, vdprintf, vfprintf, stderr
#include <poll.h>             // for pollfd, poll, POLLIN, POLLERR, POLLHUP
#include <unistd.h>           // for isatty, read, write, STDIN_FILENO
#include <string.h>           // for strerror, strlen, memset
#include <sys/ioctl.h>        // for ioctl, winsize, TIOCGWINSZ
#include <termios.h>          // for tcsetattr, tcgetattr, cc_t
#include <errno.h>            // for errno

#include "cne_tty.h"        // for cne_osal

static cne_tty_t __cne_tty;
cne_tty_t *this_tty = &__cne_tty;

int
tty_is_inited(void)
{
    return (this_tty->flags & TTY_IS_INITED);
}

void
tty_set_wchanged(void)
{
    atomic_store(&this_tty->winsz, 1);
}

void
tty_clear_wchanged(void)
{
    atomic_store(&this_tty->winsz, 0);
}

int
tty_did_wchange(void)
{
    return atomic_exchange(&this_tty->winsz, 0);
}

tty_wsize_t *
tty_window_size(void)
{
    if (!this_tty)
        return NULL;

    return &this_tty->wsize;
}

int
tty_num_rows(void)
{
    return this_tty->wsize.nrows;
}

int
tty_num_columns(void)
{
    return this_tty->wsize.ncols;
}

void
tty_enable_color(void)
{
    this_tty->flags |= TTY_COLOR_ON;
}

void
tty_disable_color(void)
{
    this_tty->flags &= ~TTY_COLOR_ON;
}

int
tty_is_color_on(void)
{
    return this_tty->flags & TTY_COLOR_ON;
}

int
tty_dwrite(int fd, const char *buf, int len)
{
    return write(fd, buf, len);
}

int
tty_write(const char *buf, int len)
{
    if (len <= 0)
        len = strlen(buf);
    return (!this_tty) ? -1 : tty_dwrite(this_tty->fd_out, buf, len);
}

int
tty_fwrite(FILE *f, const char *buf, int len)
{
    if (len <= 0)
        len = strlen(buf);
    return fwrite(buf, 1, len, f);
}

int
tty_dread(int fd, char *buf, int len)
{
    return read(fd, buf, len);
}

int
tty_read(char *buf, int len)
{
    return (!this_tty) ? -1 : tty_dread(this_tty->fd_in, buf, len);
}

int
tty_fread(FILE *f, char *buf, int len)
{
    return fread(buf, 1, len, f);
}

int
tty_poll(char *buf, int len, int timeout)
{
    struct pollfd fds;
    int ret;

    fds.fd      = this_tty->fd_in;
    fds.events  = POLLIN;
    fds.revents = 0;

    ret = poll(&fds, 1, timeout); /* 100ms */
    if (ret == 0)
        return 0;

    if (ret < 0)
        return -1;

    if ((fds.revents & (POLLERR | POLLNVAL)) == 0) {
        if ((fds.revents & POLLHUP))
            return -1;
        else if ((fds.revents & POLLIN))
            return tty_read(buf, len);
    } else
        return -1;

    return 0;
}

int
tty_printf(const char *fmt, ...)
{
    va_list vaList;
    int ret;

    va_start(vaList, fmt);
    ret = vdprintf(this_tty->fd_out, fmt, vaList);
    va_end(vaList);

    return ret;
}

int
tty_vprintf(const char *fmt, va_list ap)
{
    return vdprintf(this_tty->fd_out, fmt, ap);
}

int
tty_fprintf(FILE *f, const char *fmt, ...)
{
    va_list vaList;
    int ret = -1;

    if (f) {
        va_start(vaList, fmt);
        ret = vfprintf(f, fmt, vaList);
        va_end(vaList);
    }
    return ret;
}

int
tty_vfprintf(FILE *f, const char *fmt, va_list ap)
{
    return (!f) ? -1 : vfprintf(f, fmt, ap);
}

static void
handle_winch(int sig)
{
    if (sig == SIGWINCH) {
        struct winsize w;

        ioctl(this_tty->fd_in, TIOCGWINSZ, &w);

        this_tty->wsize.nrows = w.ws_row;
        this_tty->wsize.ncols = w.ws_col;

        tty_set_wchanged();
    }
}

static void
tty_raw_input(void)
{
    struct termios term = {0};

    term = this_tty->oldterm;

    term.c_lflag &= ~(ICANON | ECHO | IEXTEN);
    term.c_cc[VMIN]  = 1;
    term.c_cc[VTIME] = 0;

    if (tcsetattr(this_tty->fd_in, TCSANOW, &term) < 0)
        fprintf(stderr, "%s: failed to set tty: %s\n", __func__, strerror(errno));
    else
        this_tty->flags |= TTY_IS_A_TTY;
}

static void
tty_reset(void)
{
    if (this_tty->flags & TTY_IS_A_TTY) {
        if (tcsetattr(this_tty->fd_in, TCSANOW, &this_tty->oldterm) < 0) {
            fprintf(stderr, "%s: tcsetattr(%d) failed: %s\n", __func__, this_tty->fd_in,
                    strerror(errno));
            return;
        }
        this_tty->flags &= ~TTY_IS_A_TTY;
    }
}

int
tty_setup(int fd_in, int fd_out)
{
    if (!(this_tty->flags & TTY_IS_INITED))
        return -1;

    tty_reset();

    this_tty->fd_in  = (fd_in == -1) ? STDIN_FILENO : fd_in;
    this_tty->fd_out = (fd_out == -1) ? STDOUT_FILENO : fd_out;

    if (isatty(this_tty->fd_in))
        tty_raw_input();

    return 0;
}

CNE_INIT_PRIO(__create, INIT)
{
    memset(this_tty, 0, sizeof(cne_tty_t));

    this_tty->fd_in  = STDIN_FILENO;
    this_tty->fd_out = STDOUT_FILENO;
    this_tty->flags  = TTY_IS_INITED | TTY_COLOR_ON;

    if (!isatty(this_tty->fd_in))
        return;

    if (tcgetattr(this_tty->fd_in, &this_tty->oldterm) < 0)
        fprintf(stderr, "%s: setup failed for tty: %s\n", __func__, strerror(errno));
    else {
        struct winsize w = {0};

        /* Ask for the current window size */
        if (ioctl(this_tty->fd_in, TIOCGWINSZ, &w) < 0)
            fprintf(stderr, "%s:%d: ioctl(TIOCGWINSZ) failed\n", __FILE__, __LINE__);
        else {
            struct sigaction sa = {0};

            this_tty->wsize.nrows = w.ws_row;
            this_tty->wsize.ncols = w.ws_col;

            /* setup callback/interrupt for when the window changes size */
            sa.sa_handler = handle_winch;
            if (sigaction(SIGWINCH, &sa, &this_tty->saved_action) < 0)
                fprintf(stderr, "%s:%d: sigaction(SIGWINCH) failed\n", __FILE__, __LINE__);
            else {
                tty_raw_input();
                return;
            }
        }
    }

    tty_destroy();
}

void
tty_destroy(void)
{
    tty_reset();

    /* Restore the old sigaction() value */
    if (this_tty->flags & TTY_IS_INITED)
        sigaction(SIGWINCH, &this_tty->saved_action, NULL);
}

CNE_FINI_PRIO(__destroy, INIT) { tty_destroy(); }
