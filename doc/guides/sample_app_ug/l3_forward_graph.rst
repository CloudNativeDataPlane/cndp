..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2020 Marvell International Ltd.

L3 Forwarding Graph Sample Application
======================================

The L3 Forwarding Graph application is an example using the CNDP graph framework. The application
performs layer 3 forwarding using nodes written for the graph framework.

Overview
--------

The application demonstrates the use of the graph framework and graph nodes ``pktdev_rx``,
``ip4_lookup``, ``ip4_rewrite``, ``pktdev_tx`` and ``pkt_drop`` to implement packet forwarding.

The forwarding logic starts from Rx, followed by LPM lookup, TTL update, and finally Tx. The
operations are implemented inside graph nodes. These nodes are interconnected using the graph
framework. The application main loop needs to walk over graph using ``cne_graph_walk()`` with graph
objects created one per worker thread.

The lookup method is done by the ``ip4_lookup`` graph node. The ID of the output interface for the
packet is the next hop returned by the LPM lookup. The set of LPM rules used by the application is
statically configured and provided to ``ip4_lookup`` graph node and ``ip4_rewrite`` graph node
using node control API ``cne_node_ip4_route_add()`` and ``cne_node_ip4_rewrite_add()``.

The sample application only supports IPv4 forwarding.

Running the Application
-----------------------

Edit the l3fwd-graph.jsonc file to change the configuration, then run::

    sudo ./builddir/examples/l3fwd-graph/l3fwd-graph -c <json-file-name>

.. _l3_fwd_graph_explanation:

Explanation
-----------

The following sections describe aspects that are specific to the L3 Forwarding Graph application.

Graph Node Pre-Init Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After device configuration is complete, the lport port ids are passed to ``cne_node_eth_config()``.
This causes the ``pktdev_rx`` and ``pktdev_tx`` nodes as to be cloned as ``pktdev_rx-X`` and
``pktdev_tx-X`` where X represents the port id associated with the node.

.. code-block:: c

    static int
    initialize(void)
    {
        uint16_t nb_conf = 0;

        CNE_INFO("pktmbuf_t size %ld, udata64 offset %ld\n", sizeof(pktmbuf_t),
                offsetof(pktmbuf_t, udata64));

        /* Pre-init dst MACs for all ports to 02:00:00:00:00:xx */
        for (uint16_t lportid = 0; lportid < pktdev_port_count(); lportid++) {
            struct ether_addr addr;

            dest_eth_addr[lportid]           = ETHER_LOCAL_ADMIN_ADDR + ((uint64_t)lportid << 40);
            *(uint64_t *)(val_eth + lportid) = dest_eth_addr[lportid];

            pktdev_conf[nb_conf++].port_id = lportid;

            if (pktdev_macaddr_get(lportid, &addr))
                CNE_ERR_RET("Unable to get MAC address from lport %d\n", lportid);

            ether_addr_copy(&addr, (struct ether_addr *)(val_eth + lportid) + 1);
        }

        /* Ethdev node config, skip rx queue mapping */
        if (cne_node_eth_config(pktdev_conf, nb_conf))
            CNE_ERR_RET("cne_node_eth_config: failed\n");

        return 0;
    }

Graph Initialization
~~~~~~~~~~~~~~~~~~~~

Now a graph needs to be created with a specific set of nodes for every thread. A graph object
returned after graph creation is a per thread object and cannot be shared between threads. Since
``pktdev_tx-X`` node is per port, it can be associated with all the graphs created as all the lcores
should have Tx capability for every port. But ``pktdev_rx-X`` node is created per lport.

.. note::

    The Graph creation will fail if the passed set of shell node patterns
    are not sufficient to meet their inter-dependency or even one node is not
    found with a given regex node pattern.

.. code-block:: c

    static int
    initialize_graph(jcfg_thd_t *thd, graph_info_t *gi)
    {
        /* Rewrite data of src and dst ether addr */
        const char *patterns[] = {"ip4*", "pktdev_tx-*", "pkt_drop", NULL};
        jcfg_lport_t *lport;
        char name[128];

        for (int i = 0; patterns[i]; i++)
            add_graph_pattern(gi, patterns[i]);

        fwd->nb_graphs++;

        foreach_thd_lport (thd, lport) {
            snprintf(name, sizeof(name), "pktdev_rx-%u", lport->lpid);
            add_graph_pattern(gi, name);
        }

        snprintf(name, sizeof(name), "worker_%d", cne_id());
        CNE_INFO("Create Graph '%s'\n", name);

        gi->id = cne_graph_create(name, gi->patterns);
        if (gi->id == CNE_GRAPH_ID_INVALID)
            CNE_ERR_GOTO(err, "cne_graph_create(): graph_id '%s' for uid %u\n", name, cne_id());

        gi->graph = cne_graph_lookup(name);
        if (!gi->graph)
            CNE_ERR_GOTO(err, "cne_graph_lookup(): graph '%s' not found\n", name);

        return 0;
    err:
        cne_graph_destroy(gi->id);
        return -1;
    }

Forwarding data(Route, Next-Hop) addition
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once graph objects are created, node specific info like routes and rewrite
headers are provided at run-time using the ``cne_node_ip4_route_add()`` and
``cne_node_ip4_rewrite_add()`` APIs.

.. note::

    Since currently ``ip4_lookup`` and ``ip4_rewrite`` nodes don't support
    lock-less mechanisms(RCU, etc) to add run-time forwarding data like route and
    rewrite data, forwarding data is added before packet processing loop is
    launched on a worker thread.

.. code-block:: c

    static int
    initialize_routes(void)
    {
        /* Rewrite data of src and dst ether addr */
        uint8_t rewrite_data[2 * sizeof(struct ether_addr)];
        uint8_t rewrite_len;

        memset(&rewrite_data, 0, sizeof(rewrite_data));
        rewrite_len = sizeof(rewrite_data);

        /* Add route to ip4 graph infra */
        for (uint16_t i = 0; i < IPV4_L3FWD_LPM_NUM_ROUTES; i++) {
            char route_str[INET6_ADDRSTRLEN * 4];
            char abuf[INET6_ADDRSTRLEN];
            struct in_addr in;
            uint32_t dst_port;

            dst_port = ipv4_l3fwd_lpm_route_array[i].if_out;

            if (!pktdev_is_valid_port(dst_port))
                break;

            in.s_addr = htonl(ipv4_l3fwd_lpm_route_array[i].ip);
            snprintf(route_str, sizeof(route_str), "%s / %d (%d)",
                    inet_ntop(AF_INET, &in, abuf, sizeof(abuf)), ipv4_l3fwd_lpm_route_array[i].depth,
                    ipv4_l3fwd_lpm_route_array[i].if_out);

            /* Use route index 'i' as next hop id */
            if (cne_node_ip4_route_add(ipv4_l3fwd_lpm_route_array[i].ip,
                                    ipv4_l3fwd_lpm_route_array[i].depth, i,
                                    CNE_NODE_IP4_LOOKUP_NEXT_REWRITE) < 0)
                CNE_ERR_RET("Unable to add ip4 route %s to graph\n", route_str);

            memcpy(rewrite_data, val_eth + dst_port, rewrite_len);

            /* Add next hop rewrite data for id 'i' */
            if (cne_node_ip4_rewrite_add(i, rewrite_data, rewrite_len, dst_port) < 0)
                CNE_ERR_RET("Unable to add next hop %u for route %s\n", i, route_str);

            CNE_INFO("Added route %s, next_hop %u\n", route_str, i);
        }
        return 0;
    }

Packet Forwarding using Graph Walk
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Now that all the device and graph configurations are done and forwarding data is updated, the worker
threads are launched from the main loop. The main loop needs to continuously call a non-blocking
API ``cne_graph_walk()`` with it's previously created graph object.

.. note::

    cne_graph_walk() will walk over all the source nodes i.e ``pktdev_rx-X``
    associated with a given graph and Receive the available packets and enqueue them
    to the following node ``ip4_lookup`` which enqueues them to ``ip4_rewrite``
    node if LPM lookup succeeds. The ``ip4_rewrite`` node updates Ethernet header
    as per next-hop data and transmits the packet via port 'Z' by enqueuing
    to ``pktdev_tx-Z`` node instance in its graph object.

.. code-block:: c

    void
    thread_func(void *arg)
    {
        jcfg_thd_t *thd = arg;
        graph_info_t *gi;

        if (thd->group->lcore_cnt > 0)
            pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &thd->group->lcore_bitmap);

        CNE_INFO("Assigned to lcore %d\n", cne_lcore_id());

        /* Wait for main thread to initialize */
        pthread_barrier_wait(&fwd->barrier);

        gi = &fwd->graph_info[cne_id()];

        if (initialize_graph(thd, gi))
            CNE_ERR_GOTO(err, "Initialize_graph() failed\n");

        if (initialize_routes())
            CNE_ERR_GOTO(err, "Initialize_routes() failed\n");

        CNE_INFO("Entering main loop on tid %d, graph %s\n", cne_id(), gi->graph->name);

        while (likely(!thd->quit))
            cne_graph_walk(gi->graph);

        return;
    err:
        pthread_barrier_wait(&fwd->barrier);
    }
