/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

/**
 * @file
 *   cndpctl a tool to connect and control CNDP applications.
 */

// IWYU pragma: no_include <bits/getopt_core.h>
// IWYU pragma: no_include <bits/getopt-c_cc.h>
// IWYU pragma: no_include <bits/termios-c_cc.h>
// IWYU pragma: no_include <bits/termios-c_lflag.h>
// IWYU pragma: no_include <bits/termios-struct.h>
// IWYU pragma: no_include <bits/termios-tcflow.h>

#include <getopt.h>            // for getopt_long, no_argument, option
#include <stdio.h>             // for printf, NULL
#include <stdlib.h>            // for exit, EXIT_FAILURE, EXIT_SUCCESS
#include <string.h>            // for memset, strnlen
#include <unistd.h>            // for STDIN_FILENO, read, write, STDOUT_FILENO
#include <signal.h>            // for sigaction, sa_handler, SIGTERM, SIGWINCH
#include <sys/epoll.h>         // for epoll_event, epoll_ctl, epoll_data_t
#include <termios.h>           // for tcsetattr, tcgetattr, cc_t
#include <bsd/string.h>        // for strlcat
#include <errno.h>             // for errno, EINTR, EPERM
#include <csock.h>             // for csock_get_fd, csock_write, csock_cfg_t

/**
 * Simple macros to simplify code and return values with messages.
 */
#define ERR_RET(...)                 \
    do {                             \
        printf("ERR: " __VA_ARGS__); \
        return -1;                   \
    } while ((0))

#define NULL_RET(...)                \
    do {                             \
        printf("ERR: " __VA_ARGS__); \
        return NULL;                 \
    } while ((0))

#define ERR_GOTO(lbl, ...)           \
    do {                             \
        printf("ERR: " __VA_ARGS__); \
        goto lbl;                    \
    } while ((0))

#define WARN(...)                     \
    do {                              \
        printf("WARN: " __VA_ARGS__); \
    } while ((0))

#define CMD_BUFFER_SIZE 256

static int window_resized;
static struct termios orig_tio;

static void
signal_handler_winch(int signum __csock_unused)
{
    window_resized = 1;
}

static void
signal_handler_term(int signum __csock_unused)
{
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_tio);
}

static void *
client_func(void *c __csock_unused)
{
    return NULL;
}

static void
usage(int err)
{
    printf("cnectl: connect to CNDP and/or execute commands\n");
    printf("  Options:\n");
    printf("    -s,--socket host  - The local domain path or host:port to use\n");
    printf("    -h,--help         - This help message\n");
    exit(err);
}

int
main(int argc, char **argv)
{
    // clang-format off
    struct option lgopts[] = {
        { "socket",     1, NULL, 's' },
        { "help",       no_argument, NULL, 'h' },
        { NULL, 0, 0, 0 }
    };
    // clang-format on
    struct epoll_event event;
    struct sigaction sa;
    struct termios tio;
    int opt, option_index = 0;
    char cmd_buff[CMD_BUFFER_SIZE + 1];
    csock_cfg_t cfg = {0};
    int efd         = -1;
    csock_t *c      = NULL;

    while ((opt = getopt_long(argc, argv, "hs:", lgopts, &option_index)) != -1) {
        switch (opt) {
        case 'h':
            usage(EXIT_SUCCESS);
            break;
        case 's': /* Setup up UDS or TCP socket to remote host:port */
            if (c) {
                printf("-s option used more then once!\n");
                exit(EXIT_FAILURE);
            }
            cfg.flags     = CSOCK_IS_CLIENT;
            cfg.host_addr = optarg;
            cfg.client_fn = client_func;

            c = csock_create(&cfg);
            if (!c)
                exit(EXIT_FAILURE);
            break;
        default:
            break;
        }
    }

    memset(cmd_buff, 0, sizeof(cmd_buff));

    if (optind < argc) {
        strlcat(cmd_buff, "silent\n", CMD_BUFFER_SIZE);
        while (optind < argc) {
            strlcat(cmd_buff, argv[optind++], CMD_BUFFER_SIZE);
            if (optind < argc)
                strlcat(cmd_buff, " ", CMD_BUFFER_SIZE);
        }
        strlcat(cmd_buff, "\nquit\n", CMD_BUFFER_SIZE);
    }

    /* Capture terminal resize events */
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = signal_handler_winch;
    if (sigaction(SIGWINCH, &sa, 0) < 0)
        ERR_GOTO(done, "setting of sigaction(SIGWINCH) failed\n");

    /* Capture SIGTERM to reset tty settings */
    sa.sa_handler = signal_handler_term;
    if (sigaction(SIGTERM, &sa, 0) < 0)
        ERR_GOTO(done, "setting of sigaction(SIGTERM) failed\n");

    /* Save the original tty state so we can restore it later */
    if (tcgetattr(STDIN_FILENO, &orig_tio) < 0)
        ERR_GOTO(done, "tcgetattr() failed\n");

    /* Tweak the tty settings */
    tio = orig_tio;

    /* echo off, canonical mode off, ext'd input processing off */
    tio.c_lflag &= ~(ECHO | ICANON | IEXTEN);
    tio.c_cc[VMIN]  = 1; /* 1 byte at a time */
    tio.c_cc[VTIME] = 0; /* no timer */

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &tio) < 0)
        ERR_GOTO(done, "tcsetattr() failed\n");

    efd = epoll_create1(0);

    event.events  = EPOLLIN | EPOLLPRI | EPOLLERR;
    event.data.fd = STDIN_FILENO;
    if (epoll_ctl(efd, EPOLL_CTL_ADD, STDIN_FILENO, &event) != 0) {
        if (errno != EPERM)
            ERR_GOTO(done, "epoll_ctl(%d) failed\n", STDIN_FILENO);
    }

    event.events  = EPOLLIN | EPOLLPRI | EPOLLERR;
    event.data.fd = csock_get_fd(c);
    if (epoll_ctl(efd, EPOLL_CTL_ADD, csock_get_fd(c), &event) != 0)
        ERR_GOTO(done, "epoll_ctl(%d) failed\n", STDIN_FILENO);

    for (;;) {
        int n;

        if ((n = epoll_wait(efd, &event, 1, -1)) < 0) {
            ERR_GOTO(done, "epoll_wait() failed\n");

            /* maybe we received a signal */
            if (errno == EINTR)
                continue;
            goto done;
        }

        if (n == 0)
            continue;

        if (cmd_buff[0]) {
            csock_write(c, cmd_buff, strnlen(cmd_buff, CMD_BUFFER_SIZE));
            cmd_buff[0] = '\0';
        }

        if (event.data.fd == STDIN_FILENO) {
            n = read(STDIN_FILENO, cmd_buff, CMD_BUFFER_SIZE);
            if (n > 0) {
                if (csock_write(c, cmd_buff, n) < 0)
                    goto done;
            } else if (n < 0)
                WARN("Read returned %d\n", n);
            else /* EOF */
                break;
        }
        if (event.data.fd == csock_get_fd(c)) {
            n = csock_read(c, cmd_buff, CMD_BUFFER_SIZE);
            if ((n < 0) || csock_eof(c) || (write(STDOUT_FILENO, cmd_buff, n) < 0))
                break;
        }
        memset(cmd_buff, 0, sizeof(cmd_buff));
    }

done:
    csock_destroy(c);

    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_tio) < 0)
        ERR_RET("tcsetattr() failed\n");

    return 0;
}
