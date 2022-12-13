..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2020 Marvell International Ltd.
    Copyright (c) 2022 Red Hat, Inc.

CNET Graph Sample Application
=============================

The CNET graph sample application demonstrated how to use a set of graph nodes
(`cnet stack library`_) to create a UDP/TCP network stack that uses channel
callbacks in user space to process TCP and UDP traffic.

Overview
--------
The application demonstrates the use of the graph framework and graph nodes:

- ``chnl_callback``
- ``chnl_recv``
- ``arp_request``
- ``eth_rx``
- ``eth_tx``
- ``ptype``
- ``ip4_input``
- ``ip4_output``
- ``ip4_forward``
- ``ip4_proto``
- ``punt_kernel``
- ``kernel_recv``
- ``gtpu_input``
- ``tcp_input``
- ``tcp_output``
- ``udp_input``
- ``udp_output``
- ``null``
- ``pkt_drop``
- ``eth_rx-X`` (where X is the port id)
- ``eth_tx-X`` (where X is the port id)


Running the Application
-----------------------

Edit the cnetfwd-graph.jsonc file to change the configuration, then run::

    sudo ./builddir/examples/cnet-graph/cnet-graph -c <json-file-name>

.. _cnet_graph_explanation:

Explanation
-----------

The following sections describe the details of the CNET Graph application.

Graph Node Pre-Init Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After device configuration is complete, the lport ids are passed to ``cnet_eth_node_config()``.
This causes the ``eth_rx`` and ``eth_tx`` nodes to be cloned as ``eth_rx-X`` and ``eth_tx-X``
where X represents the port id associated with the node. For the ``eth_rx-X`` node, this
function also clones the edges of ``eth_rx``. This function sets the ``eth_tx-X`` node as the
next node after the ``ip4_forward`` and ``ip4_output``.

.. code-block:: c

    static struct pkt_eth_node_config pkt_conf[CNE_MAX_ETHPORTS];
    static int
        initialize(void)
        {
            uint16_t nb_conf = 0;

            for (uint16_t lportid = 0; lportid < pktdev_port_count(); lportid++)
                    pkt_conf[nb_conf++].port_id = lportid;

            /* Pktdev node config, skip rx queue mapping */
            if (cnet_eth_node_config(pkt_conf, nb_conf))
                    CNE_ERR_RET("cnet_eth_node_config: failed\n");

                return 0;
        }

The application also initializes a cnet structure using ``cnet_create()``, which in turn calls
``cnet_config_create()``. This sets up the following components for the cnet stack:

- Drivers: a reference to the interfaces their pktdev information.
- Routes: a reference to the routes fib.
- Arp entries: a reference to the ARP table/fib.
- Netlink agent: populates the ARP, route, neighbour information from the Kernel.

.. code-block:: c

    /* Create the CNET stack structure*/
    cinfo->cnet = cnet_create();
    if (!cinfo->cnet)
        CNE_ERR_RET("Unable to create CNET instance\n");

Stack Initialization
~~~~~~~~~~~~~~~~~~~~
The CNET Structure is a single global structure containing information about all of the Stack
Structures ``stk_t``. Each stack instance is independent of each other except for the needed
information from the cnet structure. The ``stk_t`` structure contains information about each graph
instance, which contains a set of graph nodes for the given stack instance. Each graph instance
can contain different graph nodes. A stack instance is initialized using ``cnet_stk_initialize()``.

.. code-block:: c

    if (cnet_stk_initialize(cinfo->cnet) < 0)
        CNE_RET("cnet_stk_initialize('%s') failed\n", thd->name);

Graph Initialization
~~~~~~~~~~~~~~~~~~~~
Now a graph needs to be created with a specific set of nodes for every thread / ``stk_t``. A graph object
returned after graph creation is a per thread object and cannot be shared between threads. Since
``eth_tx-X`` node is per port, it can be associated with all the graphs created as all the lcores
should have Tx capability for every port. But ``eth_rx-X`` node is created per lport.

.. code-block:: c

    static int
    initialize_graph(jcfg_thd_t *thd, graph_info_t *gi)
    {
        obj_value_t *pattern_array;
        jcfg_lport_t *lport;
        char graph_name[CNE_GRAPH_NAMESIZE + 1];
        char node_name[CNE_GRAPH_NAMESIZE + 1];
        int ret;

        snprintf(graph_name, sizeof(graph_name), "cnet_%d", cne_id());

        if (cinfo->flags & FWD_DEBUG_STATS)
            cne_printf("[magenta]Graph Name[]: '[orange]%s[]', [magenta]Thread name [orange]%s[]\n",
                    graph_name, thd->name);
        ret = jcfg_option_array_get(cinfo->jinfo, thd->name, &pattern_array);
        if (ret < 0)
            CNE_ERR_GOTO(err, "Unable to find %s option name\n", thd->name);

        if (pattern_array->array_sz == 0)
            CNE_ERR_GOTO(err, "Thread %s does not have any graph patterns\n", thd->name);

        if (cinfo->flags & FWD_DEBUG_STATS)
            cne_printf("  [magenta]Patterns[]: ");
        for (int i = 0; i < pattern_array->array_sz; i++) {
            char *pat = pattern_array->arr[i]->str;

            if ((CNET_ENABLE_TCP == 0) && !strncasecmp("tcp*", pat, 4))
                continue;
            if (cinfo->flags & FWD_DEBUG_STATS)
                cne_printf("'[orange]%s[]' ", pat);

            if (add_graph_pattern(gi, pat))
                goto err;
        }
        if (cinfo->flags & FWD_DEBUG_STATS)
            cne_printf("\n");

        foreach_thd_lport (thd, lport) {
            snprintf(node_name, sizeof(node_name), "eth_rx-%u", lport->lpid);
            if (add_graph_pattern(gi, node_name))
                goto err;
        }

        gi->id = cne_graph_create(graph_name, gi->patterns);
        if (gi->id == CNE_GRAPH_ID_INVALID)
            CNE_ERR_GOTO(err, "cne_graph_create(): graph_id '%s' for uid %u\n", graph_name, cne_id());

        gi->graph = cne_graph_lookup(graph_name);
        if (!gi->graph)
            CNE_ERR_GOTO(err, "cne_graph_lookup(): graph '%s' not found\n", graph_name);
        this_stk->graph = gi->graph;

        free(gi->patterns);

        return 0;
    err:
        free(gi->patterns);
        cne_graph_destroy(gi->id);
        return -1;
    }

Channel Initialization
~~~~~~~~~~~~~~~~~~~~~~
Applications plug into the CNET stack using channels ( ``struct chnl`` ). The chnl structure is an
internal structure to help manage and process connections for UDP and TCP protocols. Each chnl
structure is allocated and attached to a stack instance and not shared between threads/stack instances.

.. note::
    Channels only work within a process.

The following code snippet shows the channels being created using the ``chnl_open()`` function.

.. code-block:: c

    /* Construct the options key name <thread-name>-chnl */
    snprintf(chnl_name, sizeof(chnl_name), "%s-chnl", thd->name);

    if (jcfg_option_array_get(cinfo->jinfo, chnl_name, &chnl_array) < 0)
        CNE_ERR_GOTO(skip, "Unable to find %s option name\n", thd->name);

    if (chnl_array->array_sz == 0)
        CNE_ERR_GOTO(skip, "Thread %s does not have any graph patterns\n", thd->name);

    for (int i = 0; i < chnl_array->array_sz; i++) {
        char *s = chnl_array->arr[i]->str;

        if (!s || (s[0] == '\0'))
            CNE_ERR_GOTO(err, "string is NULL or empty\n");

        if (cinfo->flags & FWD_DEBUG_STATS)
            cne_printf("'[orange]%s[]'", s);
        if (chnl_open(s, (cinfo->flags & FWD_ENABLE_UDP_CKSUM) ? CHNL_ENABLE_UDP_CHECKSUM : 0,
                      proto_callback) < 0)
            break;
        if (cinfo->flags & FWD_DEBUG_STATS)
            cne_printf("\n%-12s", "");
    }

Applications register a callback function to accept or receive packets via the call to ``chnl_open()``.
The ``chnl_recv()`` and ``chnl_send()`` functions are used to receive and send data to/from the application.
The channel callback types are shown below:

.. code-block:: c

    /** Channel callback types */
    typedef enum {
        CHNL_UDP_RECV_TYPE,   /**< Callback for receiving UDP packets */
        CHNL_UDP_CLOSE_TYPE,  /**< Callback for UDP close */
        CHNL_TCP_ACCEPT_TYPE, /**< Callback type for accepting TCP connection */
        CHNL_TCP_RECV_TYPE,   /**< Callback for receiving TCP packets */
        CHNL_TCP_CLOSE_TYPE,  /**< Callback for TCP close */
        CHNL_CALLBACK_TYPES   /**< Maximum number of callback types */
    } chnl_type_t;

Packet Forwarding using Graph Walk
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
After all the device, graph, cnet, stack and channel configurations are done and forwarding data
is updated and the worker threads are launched from the ``JCFG_THREAD_TYPE`` parsing option. The main
loop needs to continuously call a non-blocking API ``cne_graph_walk()`` with its previously created
graph object. ``cne_graph_walk()`` will walk over all the source nodes i.e ``eth_rx-X`` associated with
a given graph and Receive the available packets and enqueue them to the appropriate channel or to the
``ip4_lookup`` node, which enqueues them to ``ip4_rewrite`` node if LPM lookup succeeds. The
``ip4_rewrite`` node updates ethernet header as per next-hop data and transmits the packet via port
'Z' by enqueuing to ``eth_tx-Z`` node instance in its graph object.

CNET info
~~~~~~~~~
The following sections show how to retrieve: CNET, stack and channel information from the running stack.

.. code-block:: none

    CNDP-cli:/> info
    CNET
    drv0 --> Attach port 99 to device eth0 MAC=ec:f4:bb:c0:b6:28 (eno1:0)
        Stk-0 on lcore 4
        Stk-1 on lcore 2

.. code-block:: none

    CNDP-cli:/> proto

    Protosw Stk-0:
    idx Name         Domain   Type     Proto         CHNL-Funcs
    0 UDP          INET     DGRAM    UDP     (17)  0x7f5c3bd01ae0
    1 TCP          INET     STREAM   TCP     ( 6)  0x7f5c3bd01980

    Protosw Stk-1:
    idx Name         Domain   Type     Proto         CHNL-Funcs
    0 UDP          INET     DGRAM    UDP     (17)  0x7f5c3bd01ae0
    1 TCP          INET     STREAM   TCP     ( 6)  0x7f5c3bd01980

.. code-block:: none

    CNDP-cli:/> chnl
    CHNL: Stk-0
        Channel descriptor: 0 state Connected 0001
        pcb 0x7f5c0c00b5d0  proto 0x7f5c0c013610 options 0002 error 0
        RCV buf hiwat 1048576 lowat 1 cnt 0 cc 0
        SND buf hiwat 1048576 lowat 1 cnt 0 cc 0
        State  Flags  Proto              Foreign                Local  TTL
        Open    0080    UDP            0.0.0.0:0         0.0.0.0:5678   64
    CHNL: Stk-1
        Channel descriptor: 1 state Connected 0001
        pcb 0x7f5c1800b5d0  proto 0x7f5c18013610 options 0002 error 0
        RCV buf hiwat 1048576 lowat 1 cnt 0 cc 0
        SND buf hiwat 1048576 lowat 1 cnt 0 cc 0
        State  Flags  Proto              Foreign                Local  TTL
        Open    0080    UDP            0.0.0.0:0         0.0.0.0:5678   64

.. _`cnet stack library`: https://cndp.io/guide/prog_guide/cnet.html