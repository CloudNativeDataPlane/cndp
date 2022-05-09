#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2021-2022 Intel Corporation


# Bash script to generate jsonc file to be used with cndpfwd app
# This script is dependent on these environment variables being set:
# CNDP_DEVICES and LIST_OF_QIDS
# CNDP_DEVICES is the list of interfaces that are passed into the cndpfwd app
# When this script is used as part of a K8s deployment, the K8s device plugin
# would populate the CNDP_DEVICES environment variable.
# LIST_OF_QIDS is the list of queue IDs that are used to program ethtool filters.
# The available cores to the application are determined by
# the 'lscpu' command.

config_file=config.jsonc

CNDP_DEVICES=${CNDP_DEVICES:-net1}
CNDP_COPY_MODE=${CNDP_COPY_MODE:-false}
LIST_OF_QIDS=${LIST_OF_QIDS:-4}

num_of_interfaces=0
num_of_qids=0
num_of_lcores=0
numa_node=0
i=0
l=0

declare -a num_of_cores_in_each_numa_node
declare -a LCORE

# get list of interfaces
for net in $CNDP_DEVICES
do
    NET[num_of_interfaces++]=$net
done

# get list of qids
for qid in $LIST_OF_QIDS
do
    QID[num_of_qids++]=$qid
done

function get_lcore()
{
    l=0
    offset=0
    i=${2}
    if [ -z "${1}" ]
    then
        nic_numa_node=0
    else
        nic_numa_node=${1}
    fi
    while [ $l -lt $nic_numa_node ]
    do
       ((offset+=${num_of_cores_in_each_numa_node[l]}))
       ((l++))
    done

    index=$((offset+i%num_of_cores_in_each_numa_node[nic_numa_node]))
    echo ${LCORE[index]}

}
output=$(lscpu | grep "NUMA node[0-9] CPU")

# Parse the list of cores for each numa node and store it in an array
IFS=$':\n';
for each_output in $output
do
   if [ $((l%2)) -eq 0 ]
   then
      ((num_of_numa_nodes++))
   else
      # split the comma separated value of cores into an array
      IFS=', ' read -a list_of_numa_lcores <<< "$each_output"

      num_of_cores_in_each_numa_node[numa_node++]=${#list_of_numa_lcores[@]}
      LCORE=(${LCORE[@]} ${list_of_numa_lcores[@]})
   fi
   ((l++))
done
unset IFS

while [ $i -lt $num_of_interfaces ]
do
    regions[i]=$(cat <<EOF

                16
EOF
    )

    # create list of lports
    lports[i]=$(
    cat <<EOF

        "${NET[i]}:0": {
            "pmd": "net_af_xdp",
            "qid": ${QID[i]},
            "umem": "umem0",
            "region": ${i},
            "unprivileged": true,
            "skb_mode": ${CNDP_COPY_MODE},
            "description": "LAN ${i} port"
        }
EOF
    )

    # create list of forwarding threads
    forwarding_threads[i]=$(
    cat <<EOF

        "fwd:${i}": {
            "group": "group${i}",
            "lports": ["${NET[i]}:0"],
            "description": "Thread ${i}"
        }
EOF
    )

    nic_numa_node=$(cat /sys/class/net/${NET[i]}/device/numa_node || echo 0)
    lcore=$(get_lcore $nic_numa_node $i)

    # create list of lcore groups
    lcore_groups[i]=$(
        cat <<-EOF

        "group${i}": ["$lcore"]
EOF
        )

    ((i++))
done

IFS=$',\n';
# generate the config file:
cat <<-EOF > ${config_file}
{
    // (R) - Required entry
    // (O) - Optional entry
    // All descriptions are optional and short form is 'desc'
    // The order of the entries in this file are handled when it is parsed and the
    // entries can be in any order.

    // (R) Application information
    //    name        - (O) the name of the application
    //    description - (O) the description of the application
    "application": {
        "name": "cndpfwd",
        "description": "A simple packet forwarder for pktdev and xskdev"
    },

    // (O) Default values
    //    bufcnt - (O) UMEM default buffer count in 1K increments
    //    bufsz  - (O) UMEM buffer size in 1K increments
    //    rxdesc - (O) Number of RX ring descriptors in 1K increments
    //    txdesc - (O) Number of TX ring descriptors in 1K increments
    //    cache  - (O) MBUF Pool cache size in number of entries
    //    mtype  - (O) Memory type for mmap allocations
    "defaults": {
        "bufcnt": 16,
        "bufsz": 2,
        "rxdesc": 2,
        "txdesc": 2,
        "cache": 256,
        "mtype": "2MB"
    },

    // List of all UMEM's to be created
    // key/val - (R) The 'key' is the name of the umem for later reference.
    //               The 'val' is the object describing the UMEM buffer.
    //               Multiple umem regions can be defined.
    // A UMEM can support multiple lports using the regions array. Each lports can use
    // one of the regions.
    //    bufcnt  - (R) The number of buffers in 1K increments in the UMEM space.
    //    bufsz   - (R) The size in 1K increments of each buffer in the UMEM space.
    //    mtype   - (O) If missing or empty string or missing means use 4KB or default system pages.
    //    regions - (O) Array of sizes one per region in 1K increments, total must be <= bufcnt
    //    rxdesc  - (O) Number of RX descriptors to be allocated in 1K increments,
    //                  if not present or zero use defaults.rxdesc, normally zero.
    //    txdesc  - (O) Number of TX descriptors to be allocated in 1K increments,
    //                  if not present or zero use defaults.txdesc, normally zero.
    //    shared_umem - (O) Set to true to use xsk_socket__create_shared() API, default false
    //    description | desc - (O) Description of the umem space.
    "umems": {
        "umem0": {
            "bufcnt": $((16*$num_of_interfaces)),
            "bufsz": 2,
            "mtype": "2MB",
            "regions": [${regions[*]}
            ],
            "rxdesc": 0,
            "txdesc": 0,
            "description": "UMEM Description 0"
        }
    },

    // List of all lports to be used in the application
    // An lport is defined by a netdev/queue ID pair, which is a socket containing a Rx/Tx ring pair.
    // Each queue ID is assigned to a single socket or a socket is the lport defined by netdev/qid.
    // Note: A netdev can be shared between lports as the qid is unique per lport
    //       If netdev is not defined or empty then it must be a virtual interface and not
    //       associated with a netdev/queue ID.
    // key/val - (R) The 'key' is the logical name e.g. 'eth0:0', 'eth1:0', ... to be used by the
    //               application to reference an lport. The 'val' object contains information about
    //               each lport.
    //    netdev        - (R) The netdev device to be used, the part before the colon
    //                     must reflect the netdev name
    //    pmd           - (R) All PMDs have a name i.e. 'net_af_xdp', 'ring', ...
    //    qid           - (R) Is the queue id to use for this lport, defined by ethtool command line
    //    umem          - (R) The UMEM assigned to this lport
    //    region        - (O) UMEM region index value, default region 0
    //    busy_poll     - (O) Enable busy polling support, true or false, default false
    //    busy_polling  -     Same as above
    //    busy_timeout  - (O) 1-65535 or 0 - use default value, values in milliseconds
    //    busy_budget   - (O) 0xFFFF disabled, 0 use default, >0 budget value
    //    unprivileged  - (O) inhibit loading the BPF program if true, default false
    //    force_wakeup  - (O) force TX wakeup calls for CVL NIC, default false
    //    skb_mode      - (O) Enable XDP_FLAGS_SKB_MODE when creating af_xdp socket, forces copy mode, default false
    //    description   - (O) the description, 'desc' can be used as well
    "lports": {${lports[*]}
    },

    // (O) Define the lcore groups for each thread to run
    //     Can be integers or a string for a range of lcores
    //     e.g. [10], [10-14,16], [10-12, 14-15, 17-18, 20]
    // Names of a lcore group and its lcores assigned to the group.
    // The initial group is for the main thread of the application.
    // The default group is special and is used if a thread if not assigned to a group.
    "lcore-groups": {
        "initial": ["${LCORE[i]}"],${lcore_groups[*]},
        "default": ["${LCORE[i+1]}"]
    },

    // (O) Set of common options application defined.
    //     The Key can be any string and value can be boolean, string, array or integer
    //     An array must contain only a single value type, boolean, integer, string and
    //     can't be a nested array.
    //   pkt_api    - (O) Set the type of packet API xskdev or pktdev
    //   no-metrics - (O) Disable metrics gathering and thread
    //   no-restapi - (O) Disable RestAPI support
    //   cli        - (O) Enable/Disable CLI supported
    //   mode       - (O) Mode type [drop | rx-only], tx-only, [lb | loopback], fwd, acl-strict, acl-permissive
    //   uds_path   - (O) Path to unix domain socket to get xsk map fd
    "options": {
        "pkt_api": "xskdev",
        "no-metrics": false,
        "no-restapi": false,
        "cli": false,
        "uds_path": "/tmp/cndp.sock",
        "mode": "drop"
    },

    // List of threads to start and information for that thread. Application can start
    // it's own threads for any reason and are not required to be configured by this file.
    //
    //   Key/Val   - (R) A unique thread name.
    //                   The format is <type-string>[:<identifier>] the ':' and identifier
    //                   are optional if all thread names are unique
    //      group  - (O) The lcore-group this thread belongs to. The
    //      lports - (O) The list of lports assigned to this thread and can not shared lports.
    //      description | desc - (O) The description
    "threads": {
        "main": {
            "group": "initial",
            "description": "CLI Thread"
        },${forwarding_threads[*]}
    }
}
EOF
# > ${config_file}

ls -l ${config_file}
cat ${config_file}
