/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Marvell International Ltd.
 */
#include <string.h>           // for memset
#include <cne_graph.h>        // for cne_node_clone, cne_node_register, cne...
#include <errno.h>            // for EIO
#include <stdint.h>           // for uint16_t, uint32_t
#include <stdio.h>            // for snprintf
#include <stdlib.h>           // for calloc

#include "node_eth_api.h"            // for cne_node_pktdev_config, cne_node_eth_c...
#include "pktdev_rx_priv.h"          // for pktdev_rx_node_elem_t, pktdev_rx_get_n...
#include "pktdev_tx_priv.h"          // for pktdev_tx_node_data_get, pktdev_tx_nod...
#include "ip4_rewrite_priv.h"        // for ip4_rewrite_node_get, ip4_rewrite_set_...
#include "node_private.h"            // for node_dbg
#include "cne_log.h"                 // for CNE_LOG_DEBUG
#include "pktdev_api.h"              // for pktdev_is_valid_port

int
cne_node_eth_config(struct cne_node_pktdev_config *conf, uint16_t nb_confs)
{
    struct cne_node_register *ip4_rewrite_node;
    struct pktdev_tx_node_main *tx_node_data;
    uint16_t port_id;
    struct cne_node_register *tx_node;
    char name[CNE_NODE_NAMESIZE];
    const char *next_nodes = name;
    int i, rc;
    uint32_t id;

    ip4_rewrite_node = ip4_rewrite_node_get();
    tx_node_data     = pktdev_tx_node_data_get();
    tx_node          = pktdev_tx_node_get();
    for (i = 0; i < nb_confs; i++) {
        port_id = conf[i].port_id;

        if (!pktdev_is_valid_port(port_id))
            break;

        /* Create RX node for each lport */
        do {
            struct pktdev_rx_node_main *rx_node_data;
            struct cne_node_register *rx_node;
            pktdev_rx_node_elem_t *elem;

            rx_node_data = pktdev_rx_get_node_data_get();
            rx_node      = pktdev_rx_node_get();
            memset(name, 0, sizeof(name));
            snprintf(name, sizeof(name), "%u", port_id);

            /* Clone a new rx node with same edges as parent */
            id = cne_node_clone(rx_node->id, name);
            if (id == CNE_NODE_ID_INVALID)
                return -EIO;

            /* Add it to list of device rx nodes for lookup */
            elem = calloc(1, sizeof(pktdev_rx_node_elem_t));
            if (!elem)
                return -1;
            elem->ctx.port_id  = port_id;
            elem->nid          = id;
            elem->next         = rx_node_data->head;
            rx_node_data->head = elem;

            node_dbg("pktdev", "Rx node %s-%s: is at %u", rx_node->name, name, id);
        } while (0);

        /* Create a per port tx node from base node */
        snprintf(name, sizeof(name), "%u", port_id);

        /* Clone a new node with same edges as parent */
        id                           = cne_node_clone(tx_node->id, name);
        tx_node_data->nodes[port_id] = id;

        node_dbg("pktdev", "Tx node %s-%s: is at %u", tx_node->name, name, id);

        /* Prepare the actual name of the cloned node */
        snprintf(name, sizeof(name), "pktdev_tx-%u", port_id);

        /* Add this tx port node as next to ip4_rewrite_node */
        cne_node_edge_update(ip4_rewrite_node->id, CNE_EDGE_ID_INVALID, &next_nodes, 1);

        /* Assuming edge id is the last one alloc'ed */
        rc = ip4_rewrite_set_next(port_id, cne_node_edge_count(ip4_rewrite_node->id) - 1);
        if (rc < 0)
            return rc;
    }

    return 0;
}
