/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#include <sys/stat.h>        // for fchmod
#include <stdio.h>           // for NULL, fprintf, snprintf, fclose, fileno
#include <string.h>          // for strcmp
#include <strings.h>         // for strncasecmp
#include <unistd.h>          // for getpid
#include <stdatomic.h>

#include "display.h"
#include "cne.h"        // for powered_by, copyright_msg_short
#include "cne_log.h"
#include "txgen.h"          // for estate, txgen_version, DISABLE_STATE
#include "version.h"        // for TXGEN_VER_PREFIX

static atomic_int_least32_t pause_display; /**< Pause the update of the screen. */

/** Enable or disable the theme or color options */
enum { DISPLAY_THEME_OFF = 0, DISPLAY_THEME_ON = 1 };

static int theme_enabled = DISPLAY_THEME_ON;

/** Enable or disable the display from being updated */
enum { DISPLAY_RUNNING = 0, DISPLAY_PAUSED = 1 };

#define MAX_COLOR_NAME_SIZE    64
#define MAX_PROMPT_STRING_SIZE 64

static char prompt_str[MAX_PROMPT_STRING_SIZE] = {0};

/* String to color value mapping */
typedef struct string_color_map_s {
    const char *name; /**< Color name */
    vt_color_e color; /**< Color value for sc_{fg,bg}color() */
} string_color_map_t;

// clang-format off
string_color_map_t string_color_map[] = {
    {"black", VT_BLACK},      {"white", VT_DEFAULT_FG},
    {"red", VT_RED},          {"green", VT_GREEN},
    {"yellow", VT_YELLOW},    {"blue", VT_BLUE},
    {"magenta", VT_MAGENTA},  {"cyan", VT_CYAN},
    {"white", VT_WHITE},      {"black", VT_DEFAULT_BG},
    {"default", VT_BLACK}, /* alias */

    {"none", VT_NO_CHANGE},   {"default_fg", VT_WHITE},
    {"default_bg", VT_BLACK}, {NULL, 0}
};
// clang-format on

/* String to attribute mapping */
typedef struct string_attr_map_s {
    const char *name; /**< Attribute name */
    vt_attr_e attr;   /**< Attribute value for sc_{fg,bg}color_attr() */
} string_attr_map_t;

// clang-format off
string_attr_map_t string_attr_map[] = {
    {"off", VT_OFF},
    {"default", VT_OFF}, /* alias */
    {"bold", VT_BOLD},
    {"bright", VT_BOLD}, /* alias */
    {"underscore", VT_UNDERSCORE},
    {"underline", VT_UNDERSCORE}, /* alias */
    {"blink", VT_BLINK},
    {"reverse", VT_REVERSE},
    {"concealed", VT_CONCEALED},
    {NULL, 0}
};
// clang-format on

/* Element to color mapping */
typedef struct theme_color_map_s {
    const char *name; /**< Display element name */
    vt_color_e fg_color;
    vt_color_e bg_color;
    vt_attr_e attr;
} theme_color_map_t;

// clang-format off
theme_color_map_t theme_color_map[] = {
    /*  { "element name",       FG_COLOR,   BG_COLOR,   ATTR    } */
    {"default", VT_DEFAULT_FG, VT_DEFAULT_BG, VT_OFF},

    /*
     * Top line of the screen
     */
    {"top.spinner", VT_CYAN, VT_NO_CHANGE, VT_BOLD},
    {"top.lports", VT_GREEN, VT_NO_CHANGE, VT_BOLD},
    {"top.page", VT_WHITE, VT_NO_CHANGE, VT_BOLD},
    {"top.copyright", VT_YELLOW, VT_NO_CHANGE, VT_OFF},
    {"top.poweredby", VT_GREEN, VT_NO_CHANGE, VT_OFF},

    /*
     * Separator between displayed values and command history
     */
    {"sep.dash", VT_MAGENTA, VT_NO_CHANGE, VT_OFF},
    {"sep.text", VT_WHITE, VT_NO_CHANGE, VT_OFF},

    /*
     * Stats screen
     */
    /* Port related */
    {"stats.lport.label", VT_YELLOW, VT_NO_CHANGE, VT_BOLD},
    {"stats.lport.flags", VT_CYAN, VT_NO_CHANGE, VT_BOLD},
    {"stats.lport.data", VT_YELLOW, VT_NO_CHANGE, VT_OFF},

    {"stats.lport.status", VT_GREEN, VT_NO_CHANGE, VT_OFF},
    {"stats.lport.linklbl", VT_GREEN, VT_NO_CHANGE, VT_BOLD},
    {"stats.lport.link", VT_GREEN, VT_NO_CHANGE, VT_OFF},
    {"stats.lport.ratelbl", VT_WHITE, VT_NO_CHANGE, VT_BOLD},
    {"stats.lport.rate", VT_WHITE, VT_NO_CHANGE, VT_OFF},
    {"stats.lport.sizelbl", VT_CYAN, VT_NO_CHANGE, VT_BOLD},
    {"stats.lport.sizes", VT_CYAN, VT_NO_CHANGE, VT_OFF},
    {"stats.lport.errlbl", VT_RED, VT_NO_CHANGE, VT_BOLD},
    {"stats.lport.errors", VT_RED, VT_NO_CHANGE, VT_OFF},
    {"stats.lport.totlbl", VT_MAGENTA, VT_NO_CHANGE, VT_BOLD},
    {"stats.lport.totals", VT_MAGENTA, VT_NO_CHANGE, VT_OFF},

    /* Dynamic elements (updated every second) */
    {"stats.dyn.label", VT_MAGENTA, VT_NO_CHANGE, VT_BOLD},
    {"stats.dyn.values", VT_GREEN, VT_NO_CHANGE, VT_OFF},

    /* Static elements (only update when explicitly set to different value) */
    {"stats.stat.label", VT_GREEN, VT_NO_CHANGE, VT_OFF},
    {"stats.stat.values", VT_WHITE, VT_NO_CHANGE, VT_OFF},

    /* Total statistics */
    {"stats.total.label", VT_RED, VT_NO_CHANGE, VT_BOLD},
    {"stats.total.data", VT_MAGENTA, VT_NO_CHANGE, VT_BOLD},

    /* Colon separating labels and values */
    {"stats.colon", VT_MAGENTA, VT_NO_CHANGE, VT_BOLD},

    /* Highlight some static values */
    {"stats.rate.count", VT_YELLOW, VT_NO_CHANGE, VT_OFF},
    {"stats.mac", VT_YELLOW, VT_NO_CHANGE, VT_OFF},
    {"stats.ip", VT_CYAN, VT_NO_CHANGE, VT_OFF},

    /*
     * Misc.
     */
    {"txgen.prompt", VT_GREEN, VT_NO_CHANGE, VT_OFF},
    {NULL, 0, 0, 0}
};
// clang-format on

/* Initialize screen data structures */
/* Print out the top line on the screen */
void
display_topline(const char *msg)
{
    display_set_color("top.page");
    cne_printf_pos(1, 20, "%s", msg);
    display_set_color("top.copyright");
    cne_printf("  %s, %s", copyright_msg_short(), powered_by());
    display_set_color(NULL);
}

/* Print out the dashed line on the screen. */
void
display_dashline(int last_row)
{
    int i;

    vt_setw(last_row);
    last_row--;
    vt_pos(last_row, 1);
    display_set_color("sep.dash");
    for (i = 0; i < 79; i++)
        cne_printf_pos(last_row, i, "-");
    display_set_color("sep.text");
    cne_printf_pos(last_row, 3, " [yellow]%s[] ", txgen_version());
    display_set_color("top.poweredby");
    cne_printf(" %s ", powered_by());
    cne_printf(" PID:[yellow]%d[] ", getpid());
    display_set_color(NULL);
}

/* Look up the named color in the colormap */
static theme_color_map_t *
lookup_item(const char *elem)
{
    theme_color_map_t *result;

    if (elem == NULL)
        elem = "default";

    /* Look up colors and attributes for elem */
    for (result = theme_color_map; result->name != NULL; ++result)
        if (strncasecmp(result->name, elem, MAX_COLOR_NAME_SIZE) == 0)
            break;

    /* Report failure if element is not found */
    if (result->name == NULL)
        result = NULL;

    return result;
}

/* Changes the color to the color of the specified element */
void
display_set_color(const char *elem)
{
    theme_color_map_t *theme_color;

    if (theme_enabled == DISPLAY_THEME_OFF)
        return;

    theme_color = lookup_item(elem);
    if (theme_color == NULL) {
        cne_printf("Unknown color '%s'\n", elem ? elem : "NULL");
        return;
    }

    vt_color(theme_color->fg_color, theme_color->bg_color, theme_color->attr);
}

/* String to use as prompt, with proper ANSI color codes */
static void
__set_prompt(void)
{
    theme_color_map_t *def, *prompt;

    /* Set default return value. */
    snprintf(prompt_str, sizeof(prompt_str), "%s> ", TXGEN_VER_PREFIX);

    if ((theme_enabled == DISPLAY_THEME_ON) && !display_is_paused()) {
        /* Look up the default and prompt values */
        def    = lookup_item(NULL);
        prompt = lookup_item("txgen.prompt");

        if ((def == NULL) || (prompt == NULL))
            cne_printf("Prompt and/or default color undefined");

        else
            snprintf(prompt_str, sizeof(prompt_str), "\033[%d;%d;%dm%s>\033[%d;%d;%dm ",
                     prompt->attr, 30 + prompt->fg_color, 40 + prompt->bg_color, TXGEN_VER_PREFIX,
                     def->attr, 30 + def->fg_color, 40 + def->bg_color);
    }
}

/** Stop display from updating until resumed later */
void
display_pause(void)
{
    atomic_exchange(&pause_display, DISPLAY_PAUSED);
    __set_prompt();
}

/** Resume the display from a pause */
void
display_resume(void)
{
    atomic_exchange(&pause_display, DISPLAY_RUNNING);
    __set_prompt();
}

/* Is the display in the paused state */
int
display_is_paused(void)
{
    return atomic_load(&pause_display) == DISPLAY_PAUSED;
}

static const char *
get_name_by_color(vt_color_e color)
{
    int i;

    for (i = 0; string_color_map[i].name; i++)
        if (color == string_color_map[i].color)
            return string_color_map[i].name;
    return NULL;
}

static const char *
get_name_by_attr(vt_attr_e attr)
{
    int i;

    for (i = 0; string_attr_map[i].name; i++)
        if (attr == string_attr_map[i].attr)
            return string_attr_map[i].name;
    return NULL;
}

static vt_color_e
get_color_by_name(char *name)
{
    int i;

    for (i = 0; string_color_map[i].name; i++)
        if (strcmp(name, string_color_map[i].name) == 0)
            return string_color_map[i].color;
    return VT_UNKNOWN_COLOR;
}

static vt_attr_e
get_attr_by_name(char *name)
{
    int i;

    for (i = 0; string_attr_map[i].name; i++)
        if (strcmp(name, string_attr_map[i].name) == 0)
            return string_attr_map[i].attr;
    return VT_UNKNOWN_ATTR;
}

void
txgen_theme_show(void)
{
    int i;

    cne_printf("*** [green]Theme Color Map Names[] ([yellow]%s[]) ***\n",
               theme_enabled ? "Enabled" : "Disabled");
    cne_printf("   [magenta]%-22s %-10s %-10s %s[]\n", "name", "FG Color", "BG Color", "Attribute");
    for (i = 0; theme_color_map[i].name; i++) {
        cne_printf("   [cyan]%-24s[] [green]%-10s[] [blue]%-10s[] [yellow]%-6s[]",
                   theme_color_map[i].name, get_name_by_color(theme_color_map[i].fg_color),
                   get_name_by_color(theme_color_map[i].bg_color),
                   get_name_by_attr(theme_color_map[i].attr));
        cne_printf("     ");
        display_set_color(theme_color_map[i].name);
        cne_printf("%-s", theme_color_map[i].name);
        display_set_color(NULL);
        cne_printf("\n");
    }
}

void
txgen_theme_state(const char *state)
{
    if (estate(state) == DISABLE_STATE)
        theme_enabled = DISPLAY_THEME_OFF;
    else
        theme_enabled = DISPLAY_THEME_ON;
    __set_prompt();
}

void
txgen_set_theme_item(char *item, char *fg_color, char *bg_color, char *attr)
{
    theme_color_map_t *elem;
    vt_color_e fg, bg;
    vt_attr_e at;

    elem = lookup_item(item);

    if (elem == NULL) {
        cne_printf("Unknown item name ([red]%s[])\n", item);
        return;
    }

    fg = get_color_by_name(fg_color);
    bg = get_color_by_name(bg_color);
    at = get_attr_by_name(attr);

    if ((fg == VT_UNKNOWN_COLOR) || (bg == VT_UNKNOWN_COLOR) || (at == VT_UNKNOWN_ATTR)) {
        cne_printf("Unknown color or attribute ([red]%s, %s, %s[])\n", fg_color, bg_color, attr);
        return;
    }

    elem->fg_color = fg;
    elem->bg_color = bg;
    elem->attr     = at;
}

void
txgen_theme_save(char *filename)
{
    FILE *f;
    int i;

    f = fopen(filename, "w+");
    if (f == NULL) {
        cne_printf("Unable to open file [red]%s[]\n", filename);
        return;
    }

    for (i = 0; theme_color_map[i].name; i++) {
        const char *fg, *bg, *at;

        fg = get_name_by_color(theme_color_map[i].fg_color);
        bg = get_name_by_color(theme_color_map[i].bg_color);
        at = get_name_by_attr(theme_color_map[i].attr);
        if (fg && bg && at)
            fprintf(f, "theme %s %s %s %s\n", theme_color_map[i].name, fg, bg, at);
        else
            fprintf(f, "theme %s default_fg default_bg off\n", theme_color_map[i].name);
    }
    fprintf(f, "cls\n");

    fchmod(fileno(f), 0666);
    fclose(f);
}
