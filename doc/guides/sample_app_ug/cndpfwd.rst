..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2019-2022 Intel Corporation.

CNDPFWD Sample Application
==========================

The cndpfwd sample application is a simple example of packet processing using CNDP API. The
"pkt_api" option lets you choose among the xskdev or pktdev API. The following modes are available:

 * drop (aka rx-only)
 * loopback
 * tx-only
 * fwd
 * acl-strict
 * acl-permissive
 * tx-only-rx (TX-Only plus draining RX ring)

In forward mode ('fwd'), the destination logical port on which to forward the packet is specified by
the last octet of the destination MAC address. It should be a valid lport number 0-N. If the
destination port does not exist the packet is sent back out the port on which it was received. Both
ACL modes follow this same logic as long as packets pass ACL checks.

For the "acl-strict" and "acl-permissive" modes the application demonstrates the use of the ACL
library in CNDP. These modes allow for simple ACL classification and will create an ACL
classification table based on some hardcoded rules and will forward or drop traffic, depending on
whether it matches the classification rules set up in the ACL context. The "acl-strict" mode drops
all packets unless it matches a permit rule while the "acl-permissive" mode forwards everything
unless it matches a deny rule. Both ACL modes drop all non-IPv4 traffic unconditionally.

The creation of an AF_XDP socket involves loading of a BPF program which is a privileged operation.
In order to run the CNDP application in an unprivileged container, the privileged operations are
done by a Kubernetes device plugin. The CNDP application talks to the Kubernetes device plugin over
a unix domain socket. The path to the unix domain socket created by the device plugin is the value
of the "uds_path" attribute. The "unprivileged" flag should be true if running the CNDP app in an
unprivileged container. The sysctl param ``kernel.unprivileged_bpf_disabled`` should be 0 to perform
unprivileged BPF operations. For more details about the device plugin, please refer to
:ref:`Integration of the K8s device plugin with CNDP <integration-k8s-dp>`.

Running the Application
-----------------------

Make sure to create or edit the fwd.jsonc before running the application then to run the example in
a linux environment:

.. code-block:: console

    $ ./builddir/examples/cndpfwd/cndpfwd -c examples/cndpfwd/fwd.jsonc

.. code-block:: console

    Usage: ./builddir/examples/cndpfwd/cndpfwd [-h] [-c json_file] [-b burst] <mode>
      <mode>         Mode types [drop | rx-only], tx-only, [lb | loopback], fwd, tx-only-rx,
                     acl-strict or acl-permissive
      -a <api>       The API type to use xskdev or pktdev APIs, default is xskdev.\n"
                     The -a option overrides JSON file.\n"
      -b <burst>     Burst size. If not present default burst size 256 max 256.
      -c <json-file> The JSON configuration file
      -C             Wait on unix domain socket for JSON or JSON-C file
      -d             More debug stats are displayed
      -D             JCFG debug decoding
      -V             JCFG information verbose
      -P             JCFG debug parsing
      -h             Display the help information

To run the installed (``make install``) version of the application, please use the
provided wrapper script rcndp in the tools directory which sets the LD_LIBRARY_PATH to the
location where libraries are installed.

.. code-block:: console

    ./tools/rcndp cndpfwd -c /tmp/fwd.jsonc

Example configuration JSON file
-------------------------------

The configuration json file is located in the ``cndpfwd`` example sub-directory

.. code-block:: console

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
            "cache": 128,
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
        //    description | desc - (O) Description of the umem space.
        "umems": {
            "umem0": {
                "bufcnt": 32,
                "bufsz": 2,
                "mtype": "2MB",
                "regions": [
                    16,
                    16
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
        //    busy_timeout  - (O) 1-65535 or 0 - use default value, values in milliseconds
        //    busy_budget   - (O) 0xFFFF disabled, 0 use default, >0 budget value
        //    unprivileged  - (O) inhibit loading the BPF program if true, default false
        //    force_wakeup  - (O) force TX wakeup calls for CVL NIC, default false
        //    skb_mode      - (O) Enable XDP_FLAGS_SKB_MODE when creating af_xdp socket, forces copy mode, default false
        //    description   - (O) the description, 'desc' can be used as well
        "lports": {
            "eth0:0": {
                "pmd": "net_af_xdp",
                "qid": 11,
                "umem": "umem0",
                "region": 0,
                "description": "LAN 0 port"
            },
            "eth1:0": {
                "pmd": "net_af_xdp",
                "qid": 12,
                "umem": "umem0",
                "region": 1,
                "description": "LAN 1 port"
            }
        },

        // (O) Define the lcore groups for each thread to run
        //     Can be integers or a string for a range of lcores
        //     e.g. [10], [10-14,16], [10-12, 14-15, 17-18, 20]
        // Names of a lcore group and its lcores assigned to the group.
        // The initial group is for the main thread of the application.
        // The default group is special and is used if a thread if not assigned to a group.
        "lcore-groups": {
            "initial": [10],
            "group0": [13],
            "group1": [14],
            "default": ["15-16"]
        },

        // (O) Set of common options application defined.
        //     The Key can be any string and value can be boolean, string, array or integer
        //     An array must contain only a single value type, boolean, integer, string and
        //     can't be a nested array.
        //   pkt_api    - (O) Set the type of packet API xskdev or pktdev
        //   no-metrics - (O) Disable metrics gathering and thread
        //   no-restapi - (O) Disable RestAPI support
        //   cli        - (O) Enable/Disable CLI supported
        //   mode       - (O) Mode type [drop | rx-only], tx-only, [lb | loopback], fwd, tx-only-rx
        //                    acl-strict, acl-permissive
        //   uds_path   - (0) Path to unix domain socket to get xsk map fd
        "options": {
            "pkt_api": "xskdev",
            "no-metrics": false,
            "no-restapi": false,
            "cli": true,
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
            },
            "fwd:0": {
                "group": "group0",
                "lports": ["eth0:0"],
                "description": "Thread 0"
            },
            "fwd:1": {
                "group": "group1",
                "lports": ["eth1:0"],
                "description": "Thread 1"
            }
        }
    }


Unix Domain Socket interface
----------------------------

The `cndpfwd` sample application provides a rudimentary remote control interface
accessible through a Unix socket created under `/var/run/cndp` directory. Each
successive run will create a new socket file, formatted as `app_socket.<pid>`
where `pid` is the Process ID of the resulting `cndpfwd` application process.

It is possible to directly connect to the socket and communicate with it using
plaintext requests, and the API will respond with JSON data.

.. note::

   UDS interface will not be available if `no-metrics` option is set to `true`
   in the JSONC file.

Available UDS endpoints:

- `/` - list all available endpoints
- `/info` - lists some basic information about the `cndpfwd` process
- `/app/hostname` - returns hostname of the machine `cndpfwd` is running on
- `/app/appname` - returns application name
- `/app/threads` - lists active CNDP threads
- `/app/ports` - lists configured CNDP ports
- `/app/start` and `/app/stop` - allows starting and stopping individual threads
  by name, specified as a parameter, e.g. `/app/stop,fwd:0` (or `all` to start
  or stop all forwarding threads)
- `/metrics/port_stats` - lists metrics for `cndpfwd` app

The following UDS endpoints will only be available if ACL is enabled:

- `/acl/rules` - lists general information about the rule table
- `/acl/rules,r:<rule>` - show a specific ACL rule (indicated by its number) in
  the rule table
- `/acl/rules,p:<rule>` - show a specific page from ACL rule table (each page
  will contain at most 32 rules)
- `/acl/clear` - clears current rule table
- `/acl/add,<rule>` - adds a new rule to the rule table, formatted as:
  `<src ip>:<dest ip>:<allow|deny>`
  where source and destination IPv4 addresses are in CIDR notation, e.g. `192.168.1.0/24`
- `/acl/build` - builds the ACL rule table (requires stopping all forwarding
  threads first)

Note that the ACL rule table changes will not take effect until the "build"
command is called.
