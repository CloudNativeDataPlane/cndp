#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2022-2023 Intel Corporation


#
# Generate a jsonc file to be used with cndpfwd app
#
# This script depends on the following environment variables:
#
# CNDP_DEVICES is the space-separated list of interfaces that passed to the
# cndpfwd app. When this script is used as part of a K8s deployment, the
# K8s device plugin populates the CNDP_DEVICES environment variable.
#
# CNDP_QUEUES is the set of queue IDs used for the logical port group. Any
# format (i.e. "0-3") supported by the CNDP json string decoder is valid.
#
# CNDP_COPY_MODE can be false or true, and determines whether COPY/SKB mode is
# used for AF_XDP sockets.
#

set -euo pipefail

CNDP_DEVICES=${CNDP_DEVICES:-net1}
CNDP_QUEUES=${CNDP_QUEUES:-all}
CNDP_COPY_MODE=${CNDP_COPY_MODE:-false}

#
# Global variables. Can be accessed by any function.
#

# File to overwrite/generate
config_file=config.jsonc

# Each element is a space-separated list of netdevs for each NUMA node
declare -a netdevs_by_node

# Each element is a comma-separated list of cores for each NUMA node
declare -a lcores_by_node

# Number of NUMA nodes
declare num_numa_nodes

#
# Initialize global variables
#
function init_global_variables
{
    local i

    num_numa_nodes=$(lscpu | awk -F: '/NUMA node\(s\):/{print $2}' | xargs)
    for (( i=0; i < num_numa_nodes; i++ )); do
        netdevs_by_node[i]=
        lcores_by_node[i]=
    done

    build_netdevs_by_node
    build_lcores_by_node
}

#
# Add each netdev from CNDP_DEVICES to the per-node netdev array
#
function build_netdevs_by_node
{
    local node
    local dev

    for dev in "${CNDP_DEVICES[@]}"; do
        node=$(cat /sys/class/net/"$dev"/device/numa_node 2>/dev/null || echo 0)
        netdevs_by_node[node]="${netdevs_by_node[$node]} $dev"
    done
}

#
# Add each lcore list to the per-node lcore array
#
function build_lcores_by_node
{
	local lines
	lines=$(lscpu | awk -F: '/NUMA node[0-9] CPU\(s\):/{print $2}' | xargs)
    local line
    local i

    i=0
    for line in "${lines[@]}"; do
        lcores_by_node[i]=$line
        i=$((i+1))
    done
}

#
# Print jsonc opening brace and "application" section
#
function emit_jsonc_application
{
    cat <<-EOF > $config_file
{
    "application": {
        "name": "cndpfwd",
        "description": "A packet forwarder for pktdev and xskdev"
    },
EOF
}

#
# Print "options" section and json closing brace
#
function emit_jsonc_options
{
    cat <<-EOF >> $config_file

    "options": {
        "mode": "drop"
    }
}
EOF
}

#
# Print "lcore-groups" section
# One group per NUMA node is created with all lcores present on that node
# as long as there is at least one device assigned to that node
#
function emit_jsonc_lcore_groups
{
    local i
    local lcore_groups

    for (( i=0; i < num_numa_nodes; i++ )); do
        if [[ ${#netdevs_by_node[i]} -eq 0 ]]; then
            continue
        fi
        lcore_groups[i]=$(
        cat <<-EOF

        "node$i": ["${lcores_by_node[i]}"]

EOF
        )
    done

    IFS=$',\n'
    cat <<-EOF >> $config_file

    "lcore-groups": {${lcore_groups[*]}
    },
EOF
    unset IFS
}

#
# Print "threads" section
# One thread per NUMA node is created as long as there is at least one
# device assigned to that node
# In the future, the number of threads per node should be configurable
#
function emit_jsonc_threads
{
    local i
    local threads

    for (( i=0; i < num_numa_nodes; i++ )); do
        if [[ ${#netdevs_by_node[i]} -eq 0 ]]; then
            continue
        fi
        threads[i]=$(
        cat <<-EOF

        "fwd:$i": {
            "group": "node$i"
        }
EOF
        )
    done

    IFS=$',\n';
    cat <<-EOF >> $config_file

    "threads": {${threads[*]}
    },
EOF
    unset IFS
}

#
# Print "lport-groups" section
# One group per NUMA node is created as long as there is at least one
# device assigned to that node. The CNDP_QUEUES is a configurable set
# of queues, or the keyword "all". A logical port is created for each
# queue, and the lport is assigned to the thread.
# In the future, the number of threads per node should be configurable
#
function emit_jsonc_lport_groups
{
    local lport_groups
    local i

    for (( i=0; i < num_numa_nodes; i++ )); do
        local each_netdev
        local netdevs
        local j=0

        if [[ ${#netdevs_by_node[i]} -eq 0 ]]; then
            continue
        fi

        for each_netdev in ${netdevs_by_node[i]}; do
            netdevs[j]=\"$each_netdev\"
            j=$((j+1))
        done

        IFS=$','
        lport_groups[i]=$(
        cat <<-EOF

        "node$i": {
            "netdevs": [${netdevs[*]}],
            "queues": "$CNDP_QUEUES",
            "threads": ["fwd:$i"],
            "pmd": "net_af_xdp",
            "skb_mode": $CNDP_COPY_MODE,
        }

EOF
        )
        unset IFS
    done
    cat <<-EOF >> $config_file

    "lport-groups": {${lport_groups[*]}
    },
EOF
}

function emit_jsonc
{
    emit_jsonc_application
    emit_jsonc_lcore_groups
    emit_jsonc_threads
    emit_jsonc_lport_groups
    emit_jsonc_options
}

# Entry point
init_global_variables
emit_jsonc
