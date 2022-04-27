/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019-2022 Intel Corporation
 */

#include <unistd.h>            // for access, gettid, sysconf, F_OK, _SC_NPROCESS...
#include <limits.h>            // for PATH_MAX
#include <string.h>            // for memset
#include <stdio.h>             // for fclose, snprintf, NULL, fgets, fopen, FILE
#include <stdlib.h>            // for strtoul, atoi
#include <time.h>              // for timespec, clock_gettime, nanosleep, CLOCK_M...
#include <cne_cycles.h>        // for cne_rdtsc
#include <cne_gettid.h>
#include <cne_strings.h>        // for cne_strtok
#include <strings.h>            // for strncasecmp

#include "cne_system.h"
#include "cne_stdio.h"        // for cne_printf

#define SYS_CPU_DIR        "/sys/devices/system/cpu/cpu%u"
#define CORE_ID_FILE       "topology/core_id"
#define NUMA_NODE_PATH     "/sys/devices/system/node"
#define STAT_PID           "/proc/%d/stat"
#define NIC_NUMA_NODE_PATH "/sys/class/net/%s/device/numa_node"

static unsigned int nb_lcores;
static unsigned int nb_numa_nodes;
static uint64_t __hz;

int
cne_max_numa_nodes(void)
{
    int nodes = nb_numa_nodes;

    if (nb_numa_nodes == 0) {
        FILE *f;
        char buffer[128];

        f = popen("lscpu", "r");
        if (!f) {
            nb_numa_nodes = 1;
            return nb_numa_nodes;
        }
        memset(buffer, 0, sizeof(buffer));
        nb_numa_nodes = 1;

        while (fgets(buffer, sizeof(buffer) - 1, f) != NULL) {
            if (!strncasecmp("NUMA node(s):", buffer, 13)) {
                nb_numa_nodes = atoi(&buffer[13]);
                break;
            }
        }
        pclose(f);
        nodes = nb_numa_nodes;
    }

    return nodes;
}

/*
 * Get CPU socket id (NUMA node) for a logical core.
 *
 * This searches each nodeX directories in /sys for the symlink for the given
 * lcore_id and returns the numa node where the lcore is found. If lcore is not
 * found on any numa node, returns zero.
 */
unsigned
cne_socket_id(unsigned lcore_id)
{
    if (lcore_id == CNE_LCORE_INVALID)
        lcore_id = cne_lcore_id();

    for (int socket = 0; socket < cne_max_numa_nodes(); socket++) {
        char path[PATH_MAX];

        snprintf(path, sizeof(path), "%s/node%d/cpu%u", NUMA_NODE_PATH, socket, lcore_id);
        if (access(path, F_OK) == 0)
            return socket;
    }
    return 0;
}

unsigned
cne_socket_id_self(void)
{
    return cne_socket_id(CNE_LCORE_INVALID);
}

static int
parse_procfs_stat_value(int thread_idx, int idx, int *id)
{
    FILE *f = NULL;
    char filename[128];
    char buf[BUFSIZ];
    char *toks[64] = {0};
    int n, ret = -1;

    if (!id)
        goto leave;

    if (thread_idx == -1)
        thread_idx = gettid();

    snprintf(filename, sizeof(filename), "/proc/%d/stat", thread_idx);

    if ((f = fopen(filename, "r")) == NULL) {
        cne_printf("%s(): cannot open sysfs value %s\n", __func__, filename);
        goto leave;
    }

    if (fgets(buf, sizeof(buf), f) == NULL) {
        cne_printf("%s(): cannot read sysfs value %s\n", __func__, filename);
        goto leave;
    }

    n = cne_strtok(buf, " ", toks, sizeof(toks) / sizeof(toks[0]));
    if (n < 0) {
        cne_printf("%s(): cannot parse sysfs value %s\n", __func__, filename);
        goto leave;
    }
    if (idx > n) {
        cne_printf("%s(): parse index out of range %d only %d\n", __func__, idx, n);
        goto leave;
    }

    if (idx == 1 || idx == 2) {
        cne_printf("%s(): index %d is a string or char type\n", __func__, idx);
        goto leave;
    }

    *id = strtoul(toks[idx], NULL, 0);

    ret = 0;
leave:
    if (f)
        fclose(f);
    return ret;
}

int
cne_lcore_id(void)
{
    int lcore_id;

    if (parse_procfs_stat_value(-1, 38, &lcore_id) < 0)
        return -1;

    return lcore_id;
}

int
cne_lcore_id_by_thread(int thread_idx)
{
    int lcore_id;

    if (parse_procfs_stat_value(thread_idx, 38, &lcore_id) < 0)
        return -1;

    return lcore_id;
}

/* parse a sysfs (or other) file containing one integer value */
static int
parse_sysfs_value(const char *filename, unsigned long *val)
{
    FILE *f;
    char buf[BUFSIZ];
    char *end = NULL;

    if ((f = fopen(filename, "r")) == NULL) {
        cne_printf("%s(): Warning cannot open sysfs value %s\n", __func__, filename);
        return 0;
    }

    if (fgets(buf, sizeof(buf), f) == NULL) {
        cne_printf("%s(): cannot read sysfs value %s\n", __func__, filename);
        fclose(f);
        return -1;
    }
    *val = strtoul(buf, &end, 0);
    if ((buf[0] == '\0') || (end == NULL) || (*end != '\n')) {
        cne_printf("%s(): cannot parse sysfs value %s\n", __func__, filename);
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

/* Get the cpu core id value from the /sys/.../cpuX core_id value */
unsigned
cne_core_id(unsigned lcore_id)
{
    char path[PATH_MAX];
    unsigned long id;

    int len = snprintf(path, sizeof(path), SYS_CPU_DIR "/%s", lcore_id, CORE_ID_FILE);
    if (len <= 0 || (unsigned)len >= sizeof(path))
        goto err;
    if (parse_sysfs_value(path, &id) != 0)
        goto err;
    return (unsigned)id;

err:
    cne_printf("Error reading core id value from %s for lcore %u - assuming core 0\n", SYS_CPU_DIR,
               lcore_id);
    return 0;
}

uint16_t
cne_device_socket_id(char *netdev)
{
    char path[PATH_MAX];
    unsigned long numa;

    int len = snprintf(path, sizeof(path), NIC_NUMA_NODE_PATH, netdev);
    if (len <= 0 || (unsigned)len >= sizeof(path))
        goto err;
    if (parse_sysfs_value(path, &numa) != 0)
        goto err;
    return numa;

err:
    cne_printf("Error reading numa id value from %s\n", netdev);
    return 0;
}

unsigned int
cne_max_lcores(void)
{
    if (nb_lcores == 0) {
        int nb = sysconf(_SC_NPROCESSORS_ONLN);

        /* sysconf() could return a -EINVAL */
        nb_lcores = (nb < 0) ? 0 : (long)nb;
    }

    return nb_lcores;
}

static uint64_t
get_tsc_freq(void)
{
#define NS_PER_SEC 1E9

    struct timespec sleeptime = {.tv_nsec = NS_PER_SEC / 10}; /* 1/10 second */

    struct timespec t_start, t_end;
    uint64_t tsc_hz;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &t_start) == 0) {
        uint64_t ns, end, start = cne_rdtsc();
        nanosleep(&sleeptime, NULL);
        clock_gettime(CLOCK_MONOTONIC_RAW, &t_end);
        end = cne_rdtsc();
        ns  = ((t_end.tv_sec - t_start.tv_sec) * NS_PER_SEC);
        ns += (t_end.tv_nsec - t_start.tv_nsec);

        double secs = (double)ns / NS_PER_SEC;
        tsc_hz      = (uint64_t)((end - start) / secs);
        return tsc_hz;
    }
    return 0;
}

uint64_t
cne_get_timer_hz(void)
{
    if (__hz == 0)
        __hz = get_tsc_freq();

    return __hz;
}
