/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation.
 */

#ifndef _CLI_H_
#define _CLI_H_

/**
 * @file
 *
 * CNE Command line interface
 */

#include <libgen.h>
#include <sys/queue.h>         // for TAILQ_HEAD, CIRCLEQ_HEAD, TAILQ_ENTRY
#include <cne_common.h>        // for CNDP_API, __cne_cache_aligned
#include <cne_log.h>           // for CNE_ASSERT
#include <cli_common.h>
#include <cli_env.h>        // for cli_sfunc_t
#include <cli_search.h>
#include <cli_file.h>
#include <cli_gapbuf.h>
#include <cli_help.h>
#include <cli_history.h>
#include <cli_map.h>
#include <cne_strings.h>
#include <stdint.h>        // for uint32_t, uint16_t, uint8_t
#include <string.h>        // for strcat, NULL, strcpy, strdup, size_t

#include "cne_stdio.h"        // for cne_printf

#ifdef __cplusplus
extern "C" {
#endif

#define CLI_ROOT_NAME "/"
#define CLI_BIN_NAME  "bin"

enum {
    CLI_MAX_ARGVS          = 64,   /**< Max number of args to support */
    CLI_DEFAULT_NB_NODES   = 256,  /**< Default number of nodes */
    CLI_DEFAULT_HIST_LINES = 128,  /**< Default number of history lines */
    CLI_MAX_PATH_LENGTH    = 2048, /**< Max path string length */
    CLI_MAX_SCRATCH_LENGTH = 4096, /**< Max scratch space length */
    CLI_NAME_LEN           = 64,   /**< Max node name dir/cmd/file/.. */
    CLI_MAX_LIST_NODES     = 128,  /**< Max number of nodes to list */
    CLI_MAX_BINS           = 32,   /**< Max number of bin directories */
    CLI_DEFAULT_NODES      = 0,    /**< Use default node count */
    CLI_SCREEN_WIDTH       = 80    /**< Size of screen width */
};

#define CLI_RECURSE_FLAG   (1 << 0)
#define CLI_LONG_LIST_FLAG (1 << 1)

/*! bitmap for the node type */
typedef enum {
    CLI_UNK_NODE   = 0x0000, /**< Unknown node type */
    CLI_DIR_NODE   = 0x0001, /**< Directory node type */
    CLI_CMD_NODE   = 0x0002, /**< Command node type */
    CLI_FILE_NODE  = 0x0004, /**< File node type */
    CLI_ALIAS_NODE = 0x0008, /**< Alias node type */
    CLI_STR_NODE   = 0x0010, /**< String node type */
} node_type_t;

/* Keep this list in sync with the node_type_t enum above */
#define CLI_NODE_TYPES                                                     \
    {                                                                      \
        "Unknown", "Directory", "Command", "File", "Alias", "String", NULL \
    }

enum {
    CLI_EXE_TYPE   = (CLI_CMD_NODE | CLI_ALIAS_NODE),
    CLI_ALL_TYPE   = (CLI_EXE_TYPE | CLI_FILE_NODE | CLI_DIR_NODE),
    CLI_OTHER_TYPE = (CLI_DIR_NODE | CLI_FILE_NODE)
};

struct cli;
struct cli_node;

typedef int (*cli_cfunc_t)(int argc, char **argv);
/**< CLI function pointer type for a command/alias node  */
typedef int (*cli_ffunc_t)(struct cli_node *node, char *buff, int len, uint32_t opt);
/**< CLI function pointer type for a file type node  */

typedef int (*cli_prompt_t)(int continuation); /**< CLI prompt routine */
typedef int (*cli_tree_t)(void);
/**< CLI function pointer type for user initialization */

/* Generic node structure for all node types in the directory tree */
struct cli_node {
    TAILQ_ENTRY(cli_node) next; /**< link list of commands */
    struct cli_node *parent;    /**< Parent directory (NULL == ROOT) */
    char name[CLI_NAME_LEN];    /**< Name of Node */
    uint16_t name_sz;           /**< Number of bytes in name w/o null */
    uint16_t fstate;            /**< File State */
    uint16_t fflags;            /**< File flags */
    uint16_t pad0;
    node_type_t type; /**< Node Type Root, Dir or cmd */
    union {
        cli_cfunc_t cfunc; /**< Function pointer for commands */
        cli_ffunc_t ffunc; /**< Function pointer for files */
        cli_sfunc_t sfunc; /**< Function pointer for Strings */
    };
    const char *short_desc;       /**< Short description */
    const char *alias_str;        /**< Alias string */
    size_t foffset;               /**< Current offset in file */
    size_t file_size;             /**< Size of file */
    char *file_data;              /**< Pointer to file data */
    TAILQ_HEAD(, cli_node) items; /**< List of nodes for directory */
} __cne_cache_aligned;            /**< Structure for each node type */

#define MAX_CMD_FILES 16

typedef struct {
    char *filename[MAX_CMD_FILES];
    uint32_t idx;
} cli_files_t;

struct cli_cfg {
    int nb_nodes; /**< Max Number of nodes to allocate */
    int nb_hist;  /**< Max Number lines in the history list */
};

struct cli {
    TAILQ_HEAD(, cli_node) root;      /**< head of node entries or root */
    CIRCLEQ_HEAD(, cli_hist) hd_hist; /**< History circular queue */

    uint32_t flags;    /**< Flags about CLI */
    uint32_t nb_nodes; /**< total number of nodes */

    uint8_t plen;    /**< Length of current prompt */
    uint8_t tab_cnt; /**< Number of tabs hit consecutively */

    uint32_t nb_hist;                    /**< total number of history lines */
    struct cli_hist *curr_hist;          /**< Current history */
    struct cli_node *bins[CLI_MAX_BINS]; /**< Arrays of bin directories,
                                    first is the current working directory */
    struct cli_node *exe_node;           /**< Node currently being executed */

    struct cli_env *env;  /**< Environment variables */
    struct gapbuf *gb;    /**< Gap buffer information */
    struct cli_vt100 *vt; /**< vt100 information */
    char **argv;          /**< array of argument string pointers */

    cli_prompt_t prompt; /**< Prompt function pointer */
    char *scratch;       /**< Place to build the path string */
    char *kill;          /**< strdup() string of last kill data */

    struct cli_node *node_mem; /**< Base address of node memory */
    struct cli_hist *hist_mem; /**< Base address of history memory */

    TAILQ_HEAD(, help_node) help_nodes; /**< head of help */
    TAILQ_HEAD(, cli_node) free_nodes;  /**< Free list of nodes */
    CIRCLEQ_HEAD(, cli_hist) free_hist; /**< free list of history nodes */
    void *user_state;                   /**< Pointer to some state variable */
} __cne_cache_aligned;

extern struct cli *this_cli;
extern cli_files_t cli_cmd_files; /**< array of command filename pointers  */

/* cli.flags */
#define CLEAR_TO_EOL    (1 << 0)
#define DISPLAY_PROMPT  (1 << 1)
#define PROMPT_CONTINUE (1 << 2)
#define DELETE_CHAR     (1 << 3)
#define CLEAR_LINE      (1 << 4)

#define CLI_USE_TIMERS      (1 << 8) /**< call timer_manage() on input */
#define CLI_NODES_UNLIMITED (1 << 9) /**< Allocate nodes with no limit */
#define CLI_YIELD_IO        (1 << 10)
#define CLI_DEFAULT_TREE    (1 << 11)

static inline void
cli_set_flag(uint32_t x)
{
    this_cli->flags |= x;
}

static inline void
cli_clr_flag(uint32_t x)
{
    this_cli->flags &= ~x;
}

static inline int
cli_tst_flag(uint32_t x)
{
    return this_cli->flags & x;
}

typedef union {
    cli_cfunc_t cfunc; /**< Function pointer for commands */
    cli_ffunc_t ffunc; /**< Function pointer for files */
    cli_sfunc_t sfunc; /**< Function pointer for strings */
} cli_funcs_t;         /* Internal: Used in argument list for adding nodes */

struct cli_dir {
    const char *name; /**< directory name */
    uint8_t bin;
};

struct cli_cmd {
    const char *name;       /**< Name of command */
    cli_cfunc_t cfunc;      /**< Function pointer */
    const char *short_desc; /**< Short description */
};                          /**< List of commands for cli_add_cmds() */

struct cli_alias {
    const char *name;       /**< Name of command */
    const char *alias_atr;  /**< Alias string */
    const char *short_desc; /**< Short description */
};                          /**< List of alias for cli_add_aliases() */

struct cli_file {
    const char *name;       /**< Name of command */
    cli_ffunc_t ffunc;      /**< Read/Write function pointer */
    const char *short_desc; /**< Short description */
};                          /**< List of alias for cli_add_aliases() */

struct cli_str {
    const char *name;   /**< Name of command */
    cli_sfunc_t sfunc;  /**< Function pointer */
    const char *string; /**< Default string */
};                      /**< List of commands for cli_add_str() */

struct cli_tree {
    node_type_t type; /**< type of node to create */
    union {
        struct cli_dir dir;     /**< directory and bin directory */
        struct cli_cmd cmd;     /**< command nodes */
        struct cli_file file;   /**< file nodes */
        struct cli_alias alias; /**< alias nodes */
        struct cli_str str;     /**< string node */
    };
};

// clang-format off
/**< Used to help create a directory tree */
#define c_dir(n)            { CLI_DIR_NODE,   .dir   = {.name = (n), .bin = 0} }
#define c_bin(n)            { CLI_DIR_NODE,   .dir   = {.name = (n), .bin = 1} }
#define c_cmd(n, f, h)      { CLI_CMD_NODE,   .cmd   = {.name = (n), .cfunc = (f), .short_desc = (h)} }
#define c_file(n, rw, h)    { CLI_FILE_NODE,  .file  = {.name = (n), .ffunc = (rw), .short_desc = (h)} }
#define c_alias(n, l, h)    { CLI_ALIAS_NODE, .alias = {.name = (n), .alias_atr = (l), .short_desc = (h)} }
#define c_str(n, f, s)      { CLI_STR_NODE,   .str   = {.name = (n), .sfunc = (f), .string = (s)} }
#define c_end()             { CLI_UNK_NODE,   .dir   = { NULL } }
// clang-format on

static inline void
cli_set_user_state(void *val)
{
    this_cli->user_state = val;
}

/**
 * CLI root directory node.
 *
 * @return
 *   Pointer to current working directory.
 */
static inline struct cli_node *
get_root(void)
{
    CNE_ASSERT(this_cli != NULL);
    return this_cli->root.tqh_first;
}

/**
 * CLI current working directory.
 *
 * @return
 *   Pointer to current working directory.
 */
static inline struct cli_node *
get_cwd(void)
{
    CNE_ASSERT(this_cli != NULL);
    return this_cli->bins[0];
}

/**
 * set CLI current working directory.
 *
 * @param node
 *   Pointer to set as the current working directory
 */
static inline void
set_cwd(struct cli_node *node)
{
    CNE_ASSERT(this_cli != NULL);
    this_cli->bins[0] = node;
}

/**
 * Check if this_cli pointer is valid
 *
 * @return
 *    1 if true else 0
 */
static inline int
is_cli_valid(void)
{
    return (this_cli) ? 1 : 0;
}

/**
 * Helper routine to compare two strings exactly
 *
 * @param s1
 *   Pointer to first string.
 * @param s2
 *   Pointer to second string.
 * @return
 *   0 failed to compare and 1 is equal.
 */
static inline int
is_match(const char *s1, const char *s2)
{
    if (!s1 || !s2)
        return 0;

    while ((*s1 != '\0') && (*s2 != '\0')) {
        if (*s1++ != *s2++)
            return 0;
    }
    if (*s1 != *s2)
        return 0;

    return 1;
}

/**
 * Test if the node is of a given type(s)
 *
 * @param node
 *   Pointer the cli_node structure
 * @param types
 *   TODO
 * @return
 *   True if node is one of the types given
 */
static inline int
is_node(struct cli_node *node, uint32_t types)
{
    return node->type & types;
}

/**
 * Test if the node is a command
 *
 * @param node
 *   Pointer the cli_node structure
 * @return
 *   True if command else false if not
 */
static inline int
is_command(struct cli_node *node)
{
    return is_node(node, CLI_CMD_NODE);
}

/**
 * Test if the node is alias
 *
 * @param node
 *   Pointer the cli_node structure
 * @return
 *   True if alias else false if not
 */
static inline int
is_alias(struct cli_node *node)
{
    return is_node(node, CLI_ALIAS_NODE);
}

/**
 * Test if the node is a file
 *
 * @param node
 *   Pointer the cli_node structure
 * @return
 *   True if a file else false if not
 */
static inline int
is_file(struct cli_node *node)
{
    return is_node(node, CLI_FILE_NODE);
}

/**
 * Test if the node is directory
 *
 * @param node
 *   Pointer the cli_node structure
 * @return
 *   True if directory else false if not
 */
static inline int
is_directory(struct cli_node *node)
{
    return is_node(node, CLI_DIR_NODE);
}

/**
 * Test if the node is executable
 *
 * @param node
 *   Pointer the cli_node structure
 * @return
 *   True if executable else false if not
 */
static inline int
is_executable(struct cli_node *node)
{
    return is_command(node) || is_alias(node);
}

/**
 * Print out the short description for commands.
 *
 * @return
 *   -1 just to remove code having to return error anyway.
 */
static inline int
cli_usage(void)
{
    if (this_cli && this_cli->exe_node) {
        const char *p = this_cli->exe_node->short_desc;

        cne_printf("  Usage: %s\n", (p) ? p : "No description found");
    }
    return -1;
}

/**
 * Return the string for the given node type
 *
 * @param node
 *   struct cli_node pointer
 * @return
 *   String for the node type.
 */
static inline const char *
cli_node_type(struct cli_node *node)
{
    const char *node_str[] = CLI_NODE_TYPES;
    switch (node->type) {
    case CLI_UNK_NODE:
    default:
        break;
    case CLI_DIR_NODE:
        return node_str[1];
    case CLI_CMD_NODE:
        return node_str[2];
    case CLI_FILE_NODE:
        return node_str[3];
    case CLI_ALIAS_NODE:
        return node_str[4];
    }
    return node_str[0];
}

/**
 * Create the current working directory string, which is the complete
 * path to node. Uses CLI routines to output the string to the console.
 *
 * @param node
 *   Starting node or last file/dir to be printed
 * @param path
 *   Pointer to a path buffer string.
 * @return
 *   Return the pointer to the cli->scratch buffer or buf with path string.
 */
static inline char *
cli_path_string(struct cli_node *node, char *path)
{
    if (!path)
        path = this_cli->scratch;

    if (!node)
        node = get_cwd();

    if (node->parent) {
        cli_path_string(node->parent, path);
        strcat(path, node->name);
        strcat(path, "/");
    } else
        strcpy(path, "/");

    return path;
}

/**
 * path string of current working directory
 *
 * @return
 *   The pointer the current working directory or NULL
 */
static inline char *
cli_cwd_path(void)
{
    return cli_path_string(get_cwd(), NULL);
}

/**
 * Print the current working directory string, which is the complete
 * path to node. Uses CLI routines to output the string to the console.
 *
 * @param node
 *   Starting node or last file/dir to be printed
 */
static inline void
cli_pwd(struct cli_node *node)
{
    cne_printf("%s", cli_path_string(node, NULL));
}

/**
 * Set the number of lines in history
 *
 * @param nb_hist
 *   Number of lines in history if zero disable history.
 * @return
 *   zero on success or -1 on error
 */
static inline int
cli_set_history_size(uint32_t nb_hist)
{
    return cli_set_history(nb_hist);
}

/**
 * Get the total number of lines in history
 *
 * @return
 *   total number of line for history
 */
static inline uint32_t
cli_get_history_size(void)
{
    return this_cli->nb_hist;
}

/**
 * List the history lines
 *
 */
static inline void
cli_history_list(void)
{
    cli_history_dump();
}

/**
 * Return the CLI root node.
 *
 * @return
 *   Pointer to root node.
 */
static inline struct cli_node *
cli_root_node(void)
{
    return this_cli->root.tqh_first;
}

/**
 * Create the CLI engine
 *
 * @param cfg
 *   The struyct cli_cfg pointer, if NULL use all default values
 * @return
 *   0 on success or -1
 */
CNDP_API int cli_create(struct cli_cfg *cfg);

/**
 * Create the CLI and add the default set of commands.
 *
 * @param cfg
 *   The struct cli_cfg pointer, can be NULL will use defaults.
 * @return
 *   -1 on error or 0 on success
 */
CNDP_API int cli_create_with_defaults(struct cli_cfg *cfg);

/**
 * Setup the CLI prompt callback and default setup function
 *
 * @param prompt
 *   The function to call when the prompt needs to be displayed
 * @param default_func
 *   The function pointer to setup the CLI files, directories and executables.
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cli_setup(cli_prompt_t prompt, cli_tree_t default_func);

/**
 * Create the CLI engine using system defaults.
 *
 * @return
 *   0 on success or -1
 */
CNDP_API int cli_setup_with_defaults(void);

/**
 * Create the CLI engine using system defaults and supplied tree init function.
 *
 * @param tree
 *   The user supplied function to init the tree or can be NULL. If NULL then
 *   a default tree is initialized with default commands.
 * @return
 *   0 on success or -1
 */
CNDP_API int cli_setup_with_tree(cli_tree_t tree);

/**
 * Set the CLI prompt function pointer
 *
 * @param prompt
 *   Function pointer to display the prompt
 * @return
 *   Return the old prompt function pointer or NULL if one does not exist
 */
CNDP_API cli_prompt_t cli_set_prompt(cli_prompt_t prompt);

/**
 * Create the root directory
 *
 * @note Uses thread variable this_cli.
 *
 * @param dirname
 *   Name of root directory, if null uses '/'
 * @return
 *   NULL on error or the root node on success.
 */
CNDP_API struct cli_node *cli_create_root(const char *dirname);

/**
 * Create the default directory tree
 *
 * @return
 *   0 on success or non-zero on error
 */
CNDP_API int cli_default_tree_init(void);

/**
 * Destroy the CLI engine
 *
 */
CNDP_API void cli_destroy(void);

/**
 * Start the CLI running
 *
 * @param msg
 *   User message to be displayed on startup
 */
CNDP_API void cli_start(const char *msg);

/**
 * Start the CLI running and use timerss
 *
 * @param msg
 *   User message to be displayed on startup
 */
CNDP_API void cli_start_with_timers(const char *msg);

/**
 * Execute command line string in cli->input
 *
 * @return
 *   zero on success or -1 on error
 */
CNDP_API int cli_execute(void);

/**
 * Add a bin directory to the bin list
 *
 * @param node
 *   Directory to add to bin list
 * @return
 *   0 is ok, -1 is full
 */
CNDP_API int cli_add_bin(struct cli_node *node);

/**
 * Remove a bin directory from the bin list
 *
 * @param node
 *   Directory to add to bin list
 * @return
 *   0 is ok, -1 is not found
 */
CNDP_API int cli_del_bin(struct cli_node *node);

/**
 * Add a bin directory to the bin list using path
 *
 * @param path
 *   path to bin directory to add, must exist first.
 * @return
 *   0 is ok, -1 is full
 */
CNDP_API int cli_add_bin_path(const char *path);

/**
 * Add a cli directory
 *
 * @param dirname
 *   String pointing to the directory name
 * @param parent
 *   Parent node of the new directory
 * @return
 *   pointer to directory entry or NULL on error
 */
CNDP_API struct cli_node *cli_add_dir(const char *dirname, struct cli_node *parent);

/**
 * Add a command to a directory
 *
 * @param name
 *   Pointer to command name string
 * @param dir
 *   Directory node pointer
 * @param func
 *   Pointer to function to execute
 * @param short_desc
 *   Short string for help to display
 * @return
 *   NULL on error or the node address for the command
 */
CNDP_API struct cli_node *cli_add_cmd(const char *name, struct cli_node *dir, cli_cfunc_t func,
                                      const char *short_desc);

/**
 * Add an alias string or special command type
 *
 * @param name
 *   Pointer to command name string
 * @param dir
 *   Directory node pointer
 * @param line
 *   Pointer to alias string
 * @param short_desc
 *   Short string for help to display
 * @return
 *   NULL on error or the node address for the command
 */
CNDP_API struct cli_node *cli_add_alias(const char *name, struct cli_node *dir, const char *line,
                                        const char *short_desc);

/**
 * Add an file to a directory
 *
 * @param name
 *   Pointer to command name string
 * @param dir
 *   Directory node pointer
 * @param func
 *   Pointer to a function attached to the file.
 * @param short_desc
 *   Short string for help to display
 * @return
 *   NULL on error or the node pointer.
 */
CNDP_API struct cli_node *cli_add_file(const char *name, struct cli_node *dir, cli_ffunc_t func,
                                       const char *short_desc);

/**
 * Add a string to the system.
 *
 * @param name
 *   Pointer to command name string
 * @param func
 *   Pointer to a function attached to the string.
 * @param str
 *   Value of string if no function defined.
 * @return
 *   NULL on error or the node pointer.
 */
CNDP_API int cli_add_str(const char *name, cli_sfunc_t func, const char *str);

/**
 * Add a list of nodes to a directory
 *
 * @param dir
 *   Node pointer to directory for add commands
 * @param tree
 *   Pointer to list of nodes to add to the tree
 * @return
 *   -1 on error or 0 for OK
 */
CNDP_API int cli_add_tree(struct cli_node *dir, struct cli_tree *tree);

/**
 * Add filenames to the CLI command list.
 *
 * @param filename
 *    Path of command file.
 * @return
 *    0 is OK and -1 if error
 */
static inline int
cli_add_cmdfile(const char *filename)
{
    if (cli_cmd_files.idx >= MAX_CMD_FILES)
        return -1;

    cli_cmd_files.filename[cli_cmd_files.idx++] = strdup(filename);

    return 0;
}

/**
 * execute a command file
 *
 * @param path
 *   Pointer to path to file
 * @return
 *   0 on OK or -1 on error
 */
CNDP_API int cli_execute_cmdfile(const char *path);

/**
 * execute a list for command files
 *
 * @return
 *   0 on OK or -1 on error
 */
CNDP_API int cli_execute_cmdfiles(void);

/**
 * Remove a node from the directory tree
 *
 * @param node
 *   The pointer to the node to remove
 * @return
 *   0 on OK and -1 on error
 */
CNDP_API int cli_remove_node(struct cli_node *node);

/**
 * Handle calling the timer_manage routine if trimers are enabled
 */
CNDP_API void cli_use_timers(void);

/**
 * return true if allocating unlimited nodes are enabled.
 *
 * @return
 *   non-zero if true else 0
 */
CNDP_API int cli_nodes_unlimited(void);

/**
 * Execute a command file from the CLI directories
 *
 * @param argc
 *   The number of arguments in the *argv* array
 * @param argv
 *   The array of string pointers to the arguments of the command.
 * @return
 *   0 on success or -1 on error
 */
CNDP_API int cli_execute_cmd(int argc, char **argv);

/**
 * Return the state of the CLI quit flag
 *
 * @return
 *   0 - still running or 1 - has quit.
 */
CNDP_API int cli_get_quit_flag(void);

/**
 * Set the quit flag to true to allow CLI to quit.
 *
 */
CNDP_API void cli_set_quit_flag(void);

#ifdef __cplusplus
}
#endif

#endif /* _CLI_H_ */
