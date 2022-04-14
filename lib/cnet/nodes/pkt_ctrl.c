/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2021-2022 Intel Corporation
 * Copyright (c) 2020 Marvell International Ltd.
 */
#include <string.h>           // for memset
#include <cne_graph.h>        // for cne_node_clone, cne_node_register, cne...
#include <errno.h>            // for EIO
#include <stdint.h>           // for uint16_t, uint32_t
#include <stdio.h>            // for snprintf
#include <stdlib.h>           // for calloc

#include "eth_node_api.h"        // for cne_node_pktdev_config, cne_node_eth_c...
#include "eth_rx_priv.h"         // for pktdev_rx_node_elem_t, pktdev_rx_get_n...
#include "eth_tx_priv.h"         // for pktdev_tx_node_data_get, pktdev_tx_nod...
#include "cne_log.h"             // for CNE_LOG_DEBUG
#include "pktdev_api.h"          // for pktdev_is_valid_port
#include "ip4_node_api.h"
#include "arp_request_priv.h"
#include "udp_output_priv.h"
#include "kernel_recv_priv.h"

int
cnet_eth_node_config(struct pkt_eth_node_config *conf, uint16_t nb_confs)
{
    struct cne_node_register *ip4_forward_node;
    struct cne_node_register *ip4_output_node;
    struct eth_tx_node_main *tx_node_data;
    uint16_t port_id;
    struct cne_node_register *tx_node;
    char name[CNE_NODE_NAMESIZE] = {0};
    const char *next_nodes       = name;
    uint32_t id;

    ip4_forward_node = ip4_forward_node_get();
    ip4_output_node  = ip4_output_node_get();

    tx_node_data = eth_tx_node_data_get();
    tx_node      = eth_tx_node_get();

    for (int i = 0; i < nb_confs; i++) {
        port_id = conf[i].port_id;

        if (!pktdev_is_valid_port(port_id))
            break;

        /* Create a per port tx node from base node */
        snprintf(name, sizeof(name), "%u", port_id);

        /* Create RX node for each lport */
        do {
            struct eth_rx_node_main *rx_node_data;
            struct cne_node_register *rx_node;
            eth_rx_node_elem_t *elem;

            rx_node_data = eth_rx_get_node_data_get();
            rx_node      = eth_rx_node_get();

            /* Clone a new rx node with same edges as parent */
            id = cne_node_clone(rx_node->id, name);
            if (id == CNE_NODE_ID_INVALID)
                CNE_ERR_RET_VAL(-EIO, "Unable to clone rx node %s\n", name);

            /* Add it to list of ethdev rx nodes for lookup */
            elem = calloc(1, sizeof(eth_rx_node_elem_t));
            if (!elem)
                goto err;
            elem->ctx.port_id  = port_id;
            elem->nid          = id;
            elem->next         = rx_node_data->head;
            rx_node_data->head = elem;
        } while (0);

        /* Clone a new node with same edges as parent */
        id                           = cne_node_clone(tx_node->id, name);
        tx_node_data->nodes[port_id] = id;

        /* Prepare the actual name of the cloned node */
        snprintf(name, sizeof(name), "eth_tx-%u", port_id);

        /* Add this tx port node as next output to ip4_forward_node */
        cne_node_edge_update(ip4_forward_node->id, CNE_EDGE_ID_INVALID, &next_nodes, 1);

        /* Add this tx port node as next output to ip4_output_node */
        cne_node_edge_update(ip4_output_node->id, CNE_EDGE_ID_INVALID, &next_nodes, 1);

        /* Assuming edge id is the last one alloc'ed */
        if (ip4_forward_set_next(port_id, cne_node_edge_count(ip4_forward_node->id) - 1) < 0)
            goto err;

        /* Assuming edge id is the last one alloc'ed */
        if (ip4_output_set_next(port_id, cne_node_edge_count(ip4_output_node->id) - 1) < 0)
            goto err;
    }

    return 0;
err:
    do {
        struct eth_rx_node_main *rx_node_data = eth_rx_get_node_data_get();
        eth_rx_node_elem_t *elem;

        while ((elem = rx_node_data->head) != NULL) {
            rx_node_data->head = elem->next;
            free(elem);
        }
    } while (0 /*CONSTCOND*/);
    return -1;
}
