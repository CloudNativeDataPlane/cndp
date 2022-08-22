/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _TXGEN_DISPLAY_H_
#define _TXGEN_DISPLAY_H_

#include <cne_log.h>
#include <cne.h>
#include <stdint.h>        // for uint16_t

#include "txgen.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 *
 * display_topline - Print out the top line on the screen.
 *
 * DESCRIPTION
 * Print out the top line on the screen and any other information.
 *
 * RETURNS: N/A
 */
void display_topline(const char *msg);

/**
 *
 * display_dashline - Print out the dashed line on the screen.
 *
 * DESCRIPTION
 * Print out the dashed line on the screen and any other information.
 *
 * RETURNS: N/A
 */
void display_dashline(int last_row);

/**
 *
 * display_set_color - Changes the color to the color of the specified element.
 *
 * DESCRIPTION
 * Changes the color to the color of the specified element.
 *
 * RETURNS: N/A
 */
void display_set_color(const char *elem);

/**
 *
 * txgen_set_prompt - Sets the prompt for the command line.
 * The new string will include color support if enabled, which includes
 * ANSI color codes to style the prompt according to the color theme.
 *
 * DESCRIPTION
 * None
 *
 * RETURNS: N/A
 */
void txgen_set_prompt(void);

/**
 *
 * txgen_show_theme - Display the current color theme information
 *
 * DESCRIPTION
 * Display the current color theme information with color
 *
 * RETURNS: N/A
 */
void txgen_show_theme(void);

/**
 *
 * txgen_set_theme_item - Set the given item name with the colors and attribute
 *
 * DESCRIPTION
 * Set the given theme item with the colors and attributes.
 *
 * RETURNS: N/A
 */
void txgen_set_theme_item(char *item, char *fg_color, char *bg_color, char *attr);

/**
 *
 * txgen_theme_save - Save the theme to a file.
 *
 * DESCRIPTION
 * Save a set of commands to set the theme colors and attributes.
 *
 * RETURNS: N/A
 */
void txgen_theme_save(char *filename);

/**
 *
 * txgen_theme_state - Set the current theme state.
 *
 * DESCRIPTION
 * Set the current theme state.
 *
 * RETURNS: N/A
 */
void txgen_theme_state(const char *state);

/**
 *
 * txgen_theme_show - Show the current theme state.
 *
 * DESCRIPTION
 * Show the current theme state.
 *
 * RETURNS: N/A
 */
void txgen_theme_show(void);

/**
 * Stop display from updating until resumed later
 */
CNDP_API void display_pause(void);

/**
 * Resume the display from a pause
 */
CNDP_API void display_resume(void);

/**
 * Is the display in the paused state
 */
CNDP_API int display_is_paused(void);

#ifdef __cplusplus
}
#endif

#endif /* _TXGEN_DISPLAY_H_ */
