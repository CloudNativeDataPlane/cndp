/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) <2019-2021> Intel Corporation.
 */

#ifndef __CLI_VT100_H_
#define __CLI_VT100_H_

/**
 * @file
 * CNE cursor and color support for VT100 using ANSI color escape codes.
 */

// IWYU pragma: no_include <bits/termios-struct.h>

#include <stdarg.h>        // for va_end, va_list, va_start
#include <stdint.h>        // for uint8_t
#include <stdio.h>         // for fileno, fprintf, stderr, stdin, stdout
#include <string.h>        // for strlen
#include <termios.h>
#include <unistd.h>            // for read, write
#include <cne_atomic.h>        // for atomic_exchange, atomic_int_least32_t, atomic...
#include <cne_common.h>        // for CNDP_API
#include <cne_stdio.h>         // for ESC
#include <cne_system.h>
#include <cne_tty.h>
#include <vt100_out.h>        // for ESC

#ifdef __cplusplus
extern "C" {
#endif

#define VT100_INITIALIZE -1

#define vt100_open_square '['
#define vt100_escape      0x1b
#define vt100_del         0x7f

/* Key codes */
#define vt100_word_left  ESC "b"
#define vt100_word_right ESC "f"
#define vt100_suppr      ESC "[3~"
#define vt100_tab        "\011"

/* Action codes for cli_vt100 */
#define vt100_bell     "\007"
#define vt100_bs       "\010"
#define vt100_bs_clear "\b \b"

/* Result of parsing : it must be synchronized with
 * vt100_commands[] in vt100_keys.c */
enum {
    VT100_INVALID_KEY = 0,
    VT100_KEY_UP_ARR,
    VT100_KEY_DOWN_ARR,
    VT100_KEY_RIGHT_ARR,
    VT100_KEY_LEFT_ARR,
    VT100_KEY_BKSPACE,
    VT100_KEY_RETURN,
    VT100_KEY_CTRL_A,
    VT100_KEY_CTRL_E,
    VT100_KEY_CTRL_K,
    VT100_KEY_CTRL_Y,
    VT100_KEY_CTRL_C,
    VT100_KEY_CTRL_F,
    VT100_KEY_CTRL_B,
    VT100_KEY_SUPPR,
    VT100_KEY_TAB,
    VT100_KEY_CTRL_D,
    VT100_KEY_CTRL_L,
    VT100_KEY_RETURN2,
    VT100_KEY_META_BKSPACE,
    VT100_KEY_WLEFT,
    VT100_KEY_WRIGHT,
    VT100_KEY_CTRL_W,
    VT100_KEY_CTRL_P,
    VT100_KEY_CTRL_N,
    VT100_KEY_META_D,
    VT100_KEY_CTRL_X,
    VT100_MAX_KEYS
};

extern const char *vt100_commands[];

enum vt100_parse_state {
    VT100_INIT,
    VT100_ESCAPE,
    VT100_ESCAPE_CSI,
    VT100_DONE     = -1,
    VT100_CONTINUE = -2
};

#define VT100_BUF_SIZE 8
struct cli_vt100 {
    int bufpos;                   /** Current offset into buffer */
    char buf[VT100_BUF_SIZE];     /** cli_vt100 command buffer */
    enum vt100_parse_state state; /** current cli_vt100 parser state */
};

struct vt100_cmds {
    const char *str;
    void (*func)(void);
};

/**
 * Create the cli_vt100 structure
 *
 * @return
 * Pointer to cli_vt100 structure or NULL on error
 */
CNDP_API struct cli_vt100 *vt100_setup(void);

/**
 * Destroy the cli_vt100 structure
 *
 * @param vt
 *  The pointer to the cli_vt100 structure.
 */
CNDP_API void vt100_free(struct cli_vt100 *vt);

/**
 * Input a new character.
 *
 * @param vt
 *   The pointer to the cli_vt100 structure
 * @param c
 *   The character to parse for cli_vt100 commands
 * @return
 *   -1 if the character is not part of a control sequence
 *   -2 if c is not the last char of a control sequence
 *   Else the index in vt100_commands[]
 */
CNDP_API int vt100_parse_input(struct cli_vt100 *vt, uint8_t c);

/**
 * Detect and execute vt100 command strings (Internal function)
 *
 * @param idx
 *    The vt100 command index value.
 */
CNDP_API void vt100_do_cmd(int idx);

/**
 * Locate a vt100 command from stdin keys
 *
 * @return
 *   Return the type of vt100 command found on stdin.
 */
CNDP_API struct vt100_cmds *vt100_get_cmds(void);

#ifdef __cplusplus
}
#endif

#endif /* __CLI_SCRN_H_ */
