/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corp, Inc.
 */

#include <stdio.h>           // for NULL, EOF
#include <stdint.h>          // for uintptr_t
#include <getopt.h>          // for getopt_long, option
#include <tst_info.h>        // for tst_ok, tst_error, tst_end, tst_start, TST_FA...
#include <hmap.h>            // for HMAP_NUM_TYPE, hmap_val_t, HMAP_NUM64_TYPE
#include <string.h>          // for strcmp

#include "hmap_test.h"
#include "cne_log.h"          // for CNE_ERR_GOTO, CNE_LOG_ERR
#include "cne_stdio.h"        // for cne_printf

struct val_data {
    int id;
    const char *prefix;
    const char *key;
    hmap_type_t type;
    hmap_val_t v;
} vals[] = {
    // clang-format off
    { 100,  NULL, "str",        HMAP_STR_TYPE, .v.str = (char *)(uintptr_t)"foobar" },
    { 101,  NULL, "u64",        HMAP_U64_TYPE, .v.u64 = 0x6464646464646464UL },
    { 102,  NULL, "u32",        HMAP_U32_TYPE, .v.u32 = 0x32323232U },
    { 103,  NULL, "u16",        HMAP_U16_TYPE, .v.u16 = 0x1616U },
    { 104,  NULL, "u8",         HMAP_U8_TYPE, .v.u8 = 0x08U },
    { 105,  NULL, "num",        HMAP_NUM_TYPE, .v.num = 0x12345678U },
    { 106,  NULL, "num-neg",    HMAP_NUM_TYPE, .v.num = -0x12345678U },
    { 107,  NULL, "num64",      HMAP_NUM64_TYPE, .v.num64 = 0x1234567890UL },
    { 108,  NULL, "num64-neg",  HMAP_NUM64_TYPE, .v.num64 = -0x1234567890UL },
    { 109,  NULL, "bool-true",  HMAP_NUM_TYPE, .v.boolean = 1 },
    { 110,  NULL, "bool-false", HMAP_NUM_TYPE, .v.boolean = 0 },
    { 111,  NULL, "ptr",        HMAP_NUM_TYPE, .v.ptr = (void *)0x12345 },

    { 200, "bar", "str",        HMAP_STR_TYPE, .v.str = (char *)(uintptr_t)"foobar" },
    { 201, "bar", "u64",        HMAP_U64_TYPE, .v.u64 = 0x6464646464646464UL },
    { 202, "bar", "u32",        HMAP_U32_TYPE, .v.u32 = 0x32323232U },
    { 203, "bar", "u16",        HMAP_U16_TYPE, .v.u16 = 0x1616U },
    { 204, "bar", "u8",         HMAP_U8_TYPE, .v.u8 = 0x08U },
    { 205, "bar", "num",        HMAP_NUM_TYPE, .v.num = 0x12345678U },
    { 206, "bar", "num-neg",    HMAP_NUM_TYPE, .v.num = -0x12345678U },
    { 207, "bar", "num64",      HMAP_NUM64_TYPE, .v.num64 = 0x1234567890UL },
    { 208, "bar", "num64-neg",  HMAP_NUM64_TYPE, .v.num64 = -0x1234567890UL },
    { 209, "bar", "bool-true",  HMAP_NUM_TYPE, .v.boolean = 1 },
    { 210, "bar", "bool-false", HMAP_NUM_TYPE, .v.boolean = 0 },
    { 211, "bar", "ptr",        HMAP_NUM_TYPE, .v.ptr = (void *)0x12345 },

    { 300, "foo", "str",        HMAP_STR_TYPE, .v.str = (char *)(uintptr_t)"foobar" },
    { 301, "foo", "u64",        HMAP_U64_TYPE, .v.u64 = 0x6464646464646464UL },
    { 302, "foo", "u32",        HMAP_U32_TYPE, .v.u32 = 0x32323232U },
    { 303, "foo", "u16",        HMAP_U16_TYPE, .v.u16 = 0x1616U },
    { 304, "foo", "u8",         HMAP_U8_TYPE, .v.u8 = 0x08U },
    { 305, "foo", "num",        HMAP_NUM_TYPE, .v.num = 0x12345678U },
    { 306, "foo", "num-neg",    HMAP_NUM_TYPE, .v.num = -0x12345678U },
    { 307, "foo", "num64",      HMAP_NUM64_TYPE, .v.num64 = 0x1234567890UL },
    { 308, "foo", "num64-neg",  HMAP_NUM64_TYPE, .v.num64 = -0x1234567890UL },
    { 309, "foo", "bool-true",  HMAP_NUM_TYPE, .v.boolean = 1 },
    { 310, "foo", "bool-false", HMAP_NUM_TYPE, .v.boolean = 0 },
    { 311, "foo", "ptr",        HMAP_NUM_TYPE, .v.ptr = (void *)0x12345 },
    { 0 }
    // clang-format on
};

static int
test_hmap(int flags)
{
    hmap_t *h;
    int ret;
    hmap_val_t val;

    (void)flags;

    h = hmap_create("test", 0, NULL); /* Use the default functions and capacity number */
    if (!h)
        return -1;

    cne_printf("[yellow]****[] [magenta]Insert[] [green]all of the values into the hashmap[]\n");
    for (int i = 0; vals[i].key; i++) {
        struct val_data *v = &vals[i];

        ret = 0;
        // clang-format off
        switch(v->type) {
        case HMAP_STR_TYPE:     ret = hmap_add_string(h, v->prefix, v->key, v->v.str); break;
        case HMAP_U64_TYPE:     ret = hmap_add_u64(h, v->prefix, v->key, v->v.u64); break;
        case HMAP_U32_TYPE:     ret = hmap_add_u32(h, v->prefix, v->key, v->v.u32); break;
        case HMAP_U16_TYPE:     ret = hmap_add_u16(h, v->prefix, v->key, v->v.u16); break;
        case HMAP_U8_TYPE:      ret = hmap_add_u8(h, v->prefix, v->key, v->v.u8); break;
        case HMAP_NUM_TYPE:     ret = hmap_add_num(h, v->prefix, v->key, v->v.num); break;
        case HMAP_NUM64_TYPE:   ret = hmap_add_num64(h, v->prefix, v->key, v->v.num64); break;
        case HMAP_BOOLEAN_TYPE: ret = hmap_add_bool(h, v->prefix, v->key, v->v.boolean); break;
        case HMAP_POINTER_TYPE: ret = hmap_add_pointer(h, v->prefix, v->key, v->v.ptr); break;
        default:
            ret = -1;
            CNE_ERR_GOTO(leave, "[magenta]Type [green]%d [magenta]unknown for ID [cyan]%d[]\n", v->type, v->id);
            break;
        }
        // clang-format on

        if (ret)
            CNE_ERR_GOTO(
                leave,
                "[magenta]Unable to add[] '[cyan]%s[]:[orange]%s[]' [magenta]with ID [cyan]%d[]\n",
                (v->prefix) ? v->prefix : "", v->key, v->id);
    }
    tst_ok("Insert all values\n");

    cne_printf("[yellow]****[] [magenta]Re-Insert[] [green]all of the values into the hashmap[]\n");
    for (int i = 0; vals[i].key; i++) {
        struct val_data *v = &vals[i];

        ret = 0;
        // clang-format off
        switch(v->type) {
        case HMAP_STR_TYPE:     ret = hmap_add_string(h, v->prefix, v->key, v->v.str); break;
        case HMAP_U64_TYPE:     ret = hmap_add_u64(h, v->prefix, v->key, v->v.u64); break;
        case HMAP_U32_TYPE:     ret = hmap_add_u32(h, v->prefix, v->key, v->v.u32); break;
        case HMAP_U16_TYPE:     ret = hmap_add_u16(h, v->prefix, v->key, v->v.u16); break;
        case HMAP_U8_TYPE:      ret = hmap_add_u8(h, v->prefix, v->key, v->v.u8); break;
        case HMAP_NUM_TYPE:     ret = hmap_add_num(h, v->prefix, v->key, v->v.num); break;
        case HMAP_NUM64_TYPE:   ret = hmap_add_num64(h, v->prefix, v->key, v->v.num64); break;
        case HMAP_BOOLEAN_TYPE: ret = hmap_add_bool(h, v->prefix, v->key, v->v.boolean); break;
        case HMAP_POINTER_TYPE: ret = hmap_add_pointer(h, v->prefix, v->key, v->v.ptr); break;
        default:
            ret = -1;
            CNE_ERR_GOTO(leave, "[magenta]Type [green]%d [magenta]unknown for ID [cyan]%d[]\n", v->type, v->id);
            break;
        }
        // clang-format on

        if (!ret) {
            ret = -1;
            CNE_ERR_GOTO(leave,
                         "[magenta]Able to re-insert[] '[cyan]%s[]:[orange]%s[]' [magenta]with ID "
                         "[cyan]%d[]\n",
                         (v->prefix) ? v->prefix : "", v->key, v->id);
        }
    }
    tst_ok("Re-insert all values\n");

    hmap_list_dump(NULL, 0);
    hmap_list_dump(NULL, 1);

    ret = 0;
    cne_printf("[yellow]****[] [magenta]Retrieve[] [green]all of the values of the hashmap[]\n");
    for (int i = 0; vals[i].key; i++) {
        struct val_data *v = &vals[i];

        ret = 0;
        // clang-format off
        switch(v->type) {
        case HMAP_STR_TYPE:
            ret = hmap_get_string(h, v->prefix, v->key, &val.str);
            if (ret == 0 && strcmp(val.str, v->v.str))
                ret = -1;
            break;
        case HMAP_U64_TYPE:
            ret = hmap_get_u64(h, v->prefix, v->key, &val.u64);
            if (ret == 0 && v->v.u64 != val.u64)
                ret = -1;
            break;
        case HMAP_U32_TYPE:
            ret = hmap_get_u32(h, v->prefix, v->key, &val.u32);
            if (ret == 0 && v->v.u32 != val.u32)
                ret = -1;
            break;
        case HMAP_U16_TYPE:
            ret = hmap_get_u16(h, v->prefix, v->key, &val.u16);
            if (ret == 0 && v->v.u16 != val.u16)
                ret = -1;
            break;
        case HMAP_U8_TYPE:
            ret = hmap_get_u8(h, v->prefix, v->key, &val.u8);
            if (ret == 0 && v->v.u8 != val.u8)
                ret = -1;
            break;
        case HMAP_NUM_TYPE:
            ret = hmap_get_num(h, v->prefix, v->key, &val.num);
            if (ret == 0 && v->v.num != val.num)
                ret = -1;
            break;
        case HMAP_NUM64_TYPE:
            ret = hmap_get_num64(h, v->prefix, v->key, &val.num64);
            if (ret == 0 && v->v.num64 != val.num64)
                ret = -1;
            break;
        case HMAP_BOOLEAN_TYPE:
            ret = hmap_get_bool(h, v->prefix, v->key, &val.boolean);
            if (ret == 0 && v->v.boolean != val.boolean)
                ret = -1;
            break;
        case HMAP_POINTER_TYPE:
            ret = hmap_get_pointer(h, v->prefix, v->key, &val.ptr);
            if (ret == 0 && v->v.ptr != val.ptr)
                ret = -1;
            break;
        default:
            ret = -1;
            CNE_ERR_GOTO(leave, "[magenta]Type [green]%d [magenta]unknown for ID [cyan]%d[]\n", v->type, v->id);
            break;
        }
        // clang-format on

        if (ret)
            CNE_ERR_GOTO(
                leave,
                "[magenta]Unable to get[] '[cyan]%s[]:[orange]%s[]' [magenta]with ID [cyan]%d[]\n",
                (v->prefix) ? v->prefix : "", v->key, v->id);
    }
    tst_ok("Retrieve all values\n");

    cne_printf("[yellow]****[] [magenta]Lookup[] [green]all of the values in the hashmap[]\n");
    for (int i = 0; vals[i].key; i++) {
        struct val_data *v = &vals[i];

        if ((ret = hmap_lookup(h, v->prefix, v->key, NULL)) < 0)
            CNE_ERR_GOTO(leave,
                         "[magenta]Unable to lookup[] '[cyan]%s[]:[orange]%s[]' [magenta]with ID "
                         "[cyan]%d[]\n",
                         (v->prefix) ? v->prefix : "", v->key, v->id);
    }
    tst_ok("Lookup all values\n");

    /* Delete all of the values into the hashmap */
    cne_printf("[yellow]****[] [magenta]Delete[] [green]all of the values in the hashmap[]\n");
    for (int i = 0; vals[i].key; i++) {
        struct val_data *v = &vals[i];

        if ((ret = hmap_del(h, v->prefix, v->key)) < 0)
            CNE_ERR_GOTO(leave,
                         "[magenta]Unable to delete[] '[cyan]%s[]:[orange]%s[]' [magenta]with ID "
                         "[cyan]%d[]\n",
                         (v->prefix) ? v->prefix : "", v->key, v->id);
    }
    tst_ok("Delete all values\n");

    if (hmap_destroy(h))
        tst_error("Destroy of hashmap\n");

    tst_ok("HashMap tests\n");
    return 0;

leave:
    if (h && hmap_destroy(h))
        tst_error("Destroy of hashmap\n");

    tst_error("HashMap tests\n");

    return -1;
}

int
hmap_main(int argc, char **argv)
{
    tst_info_t *tst;
    int opt, flags = 0;
    char **argvopt;
    int option_index;
    static const struct option lgopts[] = {{NULL, 0, 0, 0}};

    argvopt = argv;

    while ((opt = getopt_long(argc, argvopt, "V", lgopts, &option_index)) != EOF) {
        switch (opt) {
        case 'V':
            flags = 1;
            break;
        default:
            break;
        }
    }

    tst = tst_start("HashMap");

    if (test_hmap(flags))
        goto leave;

    tst_end(tst, TST_PASSED);

    return 0;
leave:
    tst_end(tst, TST_FAILED);
    return -1;
}
