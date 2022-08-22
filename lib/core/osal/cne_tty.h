/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef __CNE_TTY_H_
#define __CNE_TTY_H_

/**
 * @file
 * CNE TTY input and output support routines.
 *
 * Setup the TTY for I/O unless it is a socket instead. These routines are used by cli and all
 * output routines for stdin/stdout as well as socket I/O handling.
 */

// IWYU pragma: no_include <bits/termios-struct.h>

#include <termios.h>
#include <signal.h>            // for sigaction
#include <stdarg.h>            // for va_list
#include <stdint.h>            // for uint16_t
#include <stdio.h>             // for FILE
#include <string.h>            // for strlen
#include <unistd.h>            // for read, write
#include <cne_atomic.h>        // for CNE_ATOMIC
#include <cne_common.h>
#include <cne_system.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TTY_BUFF_SIZE    1024
#define TTY_MAX_CMD_SIZE 16

typedef union {
    int val;
    struct {
        uint16_t nrows; /**< Max number of rows. */
        uint16_t ncols; /**< Max number of columns. */
    };
} tty_wsize_t;

/** Structure to hold information about the tty */
typedef struct {
    int flags;                       /**< Flags for tty setup and window change */
    int fd_out;                      /**< File descriptor for output data */
    int fd_in;                       /**< File descriptor for input data */
    struct sigaction saved_action;   /**< Saved sigaction data */
    CNE_ATOMIC(uint_fast16_t) winsz; /**< Atomic value to detect a TIOCGWINSZ change */
    tty_wsize_t wsize;               /**< Window size values */
    struct termios oldterm;          /**< Old terminal setup information */
    CNE_ATOMIC(int_least32_t) pause; /**< Pause the update of the screen. */
} cne_tty_t;

enum {
    TTY_IS_INITED  = (1 << 0),
    TTY_IS_A_TTY   = (1 << 1),
    TTY_COLOR_ON   = (1 << 2),
    TTY_WS_CHANGED = (1 << 8),
};

extern cne_tty_t *this_tty;

/**
 * setup a tty or socket for user input. Default is stdin/stdout
 *
 * @param fd_in
 *   Set the tty input file descriptor, if -1 use STDIN_FILENO
 * @param fd_out
 *   Set the tty output file descriptor, if -i use STDOUT_FILENO
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int tty_setup(int fd_in, int fd_out);

/**
 * Destroy or cleanup the tty interface and handlers
 */
CNDP_API void tty_destroy(void);

/**
 * Enable color printing of messages.
 */
CNDP_API void tty_enable_color(void);

/**
 * Disable color printing of messages.
 */
CNDP_API void tty_disable_color(void);

/**
 * Test to see if color output is enabled or disabled.
 *
 * @return
 *   false if color has been disabled or true if enabled.
 */
CNDP_API int tty_is_color_on(void);

/**
 * Has the TTY been inited?
 *
 * @return
 *   true if the tty has been inited or false if not.
 */
CNDP_API int tty_is_inited(void);

/**
 * Set the window size changed flag.
 */
CNDP_API void tty_set_wchanged(void);

/**
 * Clear the window size changed flag.
 */
CNDP_API void tty_clear_wchanged(void);

/**
 * Test if the window size has changed.
 *
 * Flag is cleared when read.
 *
 * @return
 *   false if the window has not changed or true if it has changed.
 */
CNDP_API int tty_did_wchange(void);

/**
 * Get the current window size
 *
 * @return
 *   Pointer to structure or NULL if error.
 */
CNDP_API tty_wsize_t *tty_window_size(void);

/**
 * Return the number of rows in the screen
 */
CNDP_API int tty_num_rows(void);

/**
 * Return the number of columns in the screen
 */
CNDP_API int tty_num_columns(void);

/**
 * Poll the TTY input fd and return number of bytes read
 *
 * @param buf
 *   Buffer to put the input characters
 * @param len
 *   The length of the buf array
 * @param timeout
 *   The number of milli-seconds to wait or -1 for no timeout
 * @return
 *   0 - on timeout
 *   -1 - on Error
 *   Number of characters read from input.
 */
CNDP_API int tty_poll(char *buf, int len, int timeout);

/**
 * Write the data from buf to the tty file descriptor.
 *
 * @param buf
 *    Pointer to data buffer to output the file descriptor.
 * @param len
 *    Number of bytes to write to file descriptor.
 * @return
 *    The number of bytes written to the tty file descriptor
 */
CNDP_API int tty_write(const char *buf, int len);

/**
 * Write the data from buf to the tty file descriptor number, bypass this_tty->fd_out
 *
 * @param fd
 *    The file descriptor index value
 * @param buf
 *    Pointer to data buffer to output the file descriptor.
 * @param len
 *    Number of bytes to write to file descriptor.
 * @return
 *    The number of bytes written to the tty file descriptor
 */
CNDP_API int tty_dwrite(int fd, const char *buf, int len);

/**
 * Write the data from buf to the tty file descriptor, bypass this_tty->fd_out
 *
 * @param f
 *    The file descriptor pointer
 * @param buf
 *    Pointer to data buffer to output the file descriptor.
 * @param len
 *    Number of bytes to write to file descriptor.
 * @return
 *    The number of bytes written to the tty file descriptor
 */
CNDP_API int tty_fwrite(FILE *f, const char *buf, int len);

/**
 * Read the data from the tty file descriptor into the buffer.
 *
 * @param buf
 *    Pointer to data buffer to place the input from file descriptor.
 * @param len
 *    Number of bytes to read from file descriptor.
 * @return
 *    The number of bytes read from the tty file descriptor
 */
CNDP_API int tty_read(char *buf, int len);

/**
 * Read the data from the tty file descriptor into the buffer.
 *
 * @param fd
 *    The file descriptor index value
 * @param buf
 *    Pointer to data buffer to place the input from file descriptor.
 * @param len
 *    Number of bytes to read from file descriptor.
 * @return
 *    The number of bytes read from the tty file descriptor
 */
CNDP_API int tty_dread(int fd, char *buf, int len);

/**
 * Read the data from the tty file descriptor into the buffer.
 *
 * @param f
 *    The file descriptor pointer
 * @param buf
 *    Pointer to data buffer to place the input from file descriptor.
 * @param len
 *    Number of bytes to read from file descriptor.
 * @return
 *    The number of bytes read from the tty file descriptor
 */
CNDP_API int tty_fread(FILE *f, char *buf, int len);

/**
 * A printf like routine to output to tty file descriptor.
 *
 * @param fmt
 *   The formatting string for a printf like API
 */
CNDP_API int tty_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/**
 * A fprintf like routine to output to tty file descriptor.
 *
 * @param f
 *    The file descriptor pointer
 * @param fmt
 *   The formatting string for a printf like API
 */
CNDP_API int tty_fprintf(FILE *f, const char *fmt, ...) __attribute__((format(printf, 2, 0)));

/**
 * A vprintf like routine to output to tty file descriptor
 *
 * @param fmt
 *   The cne_printf() like format string.
 * @param ap
 *   The va_list pointer
 * @return
 *   The number of bytes written to the file descriptor.
 */
CNDP_API int tty_vprintf(const char *fmt, va_list ap) __attribute__((format(printf, 1, 0)));

/**
 * A vfprintf like routine to output to tty file descriptor
 *
 * @param f
 *    The file descriptor pointer
 * @param fmt
 *   The cne_printf() like format string.
 * @param ap
 *   The va_list pointer
 * @return
 *   The number of bytes written to the file descriptor.
 */
CNDP_API int tty_vfprintf(FILE *f, const char *fmt, va_list ap)
    __attribute__((format(printf, 2, 0)));

#ifdef __cplusplus
}
#endif

#endif /* __CNE_TTY_H_ */
