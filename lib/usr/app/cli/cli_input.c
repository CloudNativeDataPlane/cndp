/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <string.h>            // for strcat, strchr, strlen
#include <cne_tty.h>           // for tty_poll, tty_write
#include <bsd/string.h>        // for strlcpy

#include "cli.h"        // for cli_set_flag, this_cli, cli, cli_get_quit_flag
#include "cli_input.h"
#include "cne_log.h"          // for CNE_ASSERT
#include "cli_vt100.h"        // for vt100_do_cmd, vt100_parse_input, VT100_DONE

int
cli_yield_io(void)
{
    if (!this_cli)
        return 1;
    return this_cli->flags & CLI_YIELD_IO;
}

static void
handle_input_display(char c)
{
    /* Only allow printable characters */
    if ((c >= ' ') && (c <= '~')) {
        /* Output the character typed */
        tty_write(&c, 1);

        /* Add the character to the buffer */
        gb_insert(this_cli->gb, c);
        if (!gb_point_at_end(this_cli->gb))
            cli_set_flag(0);
        else if (!gb_point_at_start(this_cli->gb))
            cli_set_flag(0);
    }
    cli_display_line();
}

static void
handle_input(char c)
{
    /* Only allow printable characters */
    if ((c >= ' ') && (c <= '~')) {
        /* Add the character to the buffer */
        gb_insert(this_cli->gb, c);
        if (!gb_point_at_end(this_cli->gb))
            cli_set_flag(0);
        else if (!gb_point_at_start(this_cli->gb))
            cli_set_flag(0);
    }
}

/* Process the input for the CLI from the user */
void
cli_input(char *str, int n, int silent)
{
    void (*input)(char c);

    CNE_ASSERT(this_cli->gb != NULL);
    CNE_ASSERT(str != NULL);

    input = (!silent) ? handle_input_display : handle_input;

    while (n--) {
        char c = *str++;

        int ret = vt100_parse_input(this_cli->vt, c);

        if (ret > 0) { /* Found a vt100 key sequence */
            vt100_do_cmd(ret);
            input(0);
        } else if (ret == VT100_DONE)
            input(c);
    }
}

/* Poll the I/O routine for characters */
int
cli_poll(char *c)
{
    int ret;

    ret = tty_poll(c, 1, 100);
    if (ret < 0) {
        cli_set_quit_flag();
        ret = 0;
    }
    return ret;
}

/* Display a prompt and wait for a key press */
char
cli_pause(const char *msg, const char *keys)
{
    char prompt[128], c;

    prompt[0] = '\0';

    if (msg) {
        strlcpy(prompt, msg, sizeof(prompt));
        strcat(prompt, ": ");
        cne_printf("%s", prompt);
    }

    if (!keys)
        keys = " qQ\n\r" ESC;

    do {
        if (cli_poll(&c))
            if (strchr(keys, c)) {
                /* clear the line of the prompt */
                cne_printf("\r%*s\r", (int)strlen(prompt), " ");
                return c;
            }
    } while (cli_get_quit_flag() == 0);

    return '\0';
}
