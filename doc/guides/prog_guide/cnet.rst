..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2022 Intel Corporation.

.. _CNET_Library:

CNET Stack Library
==================

Overview
--------

The CNET graph node library uses a set of graph nodes to create a UDP/TCP/IPv4 network stack in
user space. One goal is to provide a network stack for applications in CNDP as the developer
may have been using the Linux network stack via the socket interface.

The CNET stack uses a socket like interface called channels to make it familiar to the developer,
but does have a number of differences. One of the differences is that channels support sending
multiple packets in a single transmission, and another is channels support receiving multiple
packets at a time using a function pointer callback.

.. note:: CNET Stack *TCP* support is **experimental** for release 22.08.

.. _figure_cndp_system_overview:

.. figure:: img/cndp_system_overview.*

   CNDP System Overview

A CNDP application runs in user-space inside a container or non-container environment (bare-metal)
and provides a set of libraries for the application developer. Please refer to the
:ref:`CNDP Overview <CNDP_Overview>`.

A number of libraries are available in CNDP and some are used in the CNET stack to provide better
performance and functionality for the application developers please refer to
:ref:`CNDP Components <CNDP_Components>` as needed.

.. note:: The *cnet-graph* example is a reasonable source on how to create an application that
  uses the CNET graph nodes. The *l3fwd-graph* example uses a different set of graph nodes then
  CNET stack, but provides another solution for a very simple packet processing application.

CNET Pod/Container Overview
---------------------------

The following CNET stack overview shows the pod/container view and where CNDP components will
be placed in a pod/container. The *Sidecar* container is used to configure and obtain statistics
for the CNDP application. The *Sidecar* container is *optional* and is not used in all applications
use cases.

.. _figure_cnet_overview:

.. figure:: img/cnet_overview.*

   CNET Pod/Container Overview

The CNET stack splits some of the processing of packets between the Linux kernel and the CNDP
application. Packets like ARP requests are handled by the Linux stack and if an ARP request is
received by the application it will need to be punted to the kernel for more processing. Other
packets not being processed by the CNET stack will be dropped or punted to the Linux kernel
via the *punt_kernel* node.

Because packets like ARP requests are being processed by the Linux stack and updating the Linux
ARP table we need a method to get this information to the CNET stack. The method being used
is the *Netlink* messages. When the kernel learns a new ARP address a *Netlink* message is sent
and the CNET stack receives these messages and updates the CNET internal tables.

A number of different *Netlink* messages are processed by the CNET stack to update ARP, routes and
interface information. This to allows CNET to learn about the system and allow the operator
to use standard Linux command line and tools i.e. ifconfig, ip, route, ... to configure the CNET stack.
The *Netlink* message processing is handled by a different thread within the application and is not
directly attached to the CNET graph node instances.

CNET Graph nodes
----------------

The CNET library contains support for UDP/TCP/IPv4 and IPv6 in the future. We have a number
of different graph nodes in CNET and creating your own graph node is very straight forward.
Please refer to :ref:`Graph Library <Graph_Library>` for more information on graph nodes.

.. note:: The packet drop node has been removed from the figure below to simplify the picture as most
  of the nodes will call packet drop if needed.

.. _figure_cnet:

.. figure:: img/cnet.*

   CNET Graph Node Layout

CNET nodes
^^^^^^^^^^

Each CNET instance (one per defined thread) is created with a set of nodes with each node handling
a number of packets at a time. Packets are processed from the inputs to the output nodes in
the :ref:`CNET Graph Nodes <figure_cnet>` in a single thread.

Input nodes like *eth_rx-N*, *kernel_recv* are called *source* nodes and are called each
time the graph is walked to get more packets to process. The *udp_output* and *tcp_output* nodes
are a special type of *source* node and are only called when the graph is walked when packets are
added to the nodes. The CNET stack uses these nodes to place outbound packet data from the
application via the *channel* APIs.

.. note:: The *chnl_callback* node calls back into the application using the same thread as the
  CNET graph instance. Processing of packets needs to be done within the CNET stack thread
  to avoid locks and race conditions.

Input Nodes
^^^^^^^^^^^

- **eth_rx-N** is the Ethernet input node and is a *source node*, which means it is called repeatedly.

  - **Note**: More then one eth_rx-N node (i.e. eth_rx-0, eth_rx-1, ...) are allowed per graph.

- **eth_tx-N** is the Ethernet output node and is called anytime packets are added to the node.

  - **Note**: More then one output node may be present (i.e. eth_tx-0, eth_tx-1, ...) are allowed per graph.

- **kernel_recv** is another source node and is called to receive packets from the kernel.
- **ptype** is the node to determine the packet type i.e. UDP/IPv4, TCP/IPv4, ... and the next node to call.
- **gtpu_input** is the node to support GTPU packets (**WiP**)
- **ip4_input** is the IPv4 input node for processing IPv4 packets, IPv6 node will be at this same level.
- **ip4_forward** is the IPv4 forwarding node for packets that have been received and can be quickly forwarded.
- **ip4_proto** is the node to determine the next node for L4 protocols i.e. UDP or TCP.
- **tcp_input** is the starting node to process TCP packets, which each packet is processed in the *cnet_tcp_input* function.

- **udp_input** is the starting node to process UDP packet, which each packet determined if it is to be processed by the graph instance.

- **chnl_recv** is the node to help send packet data processed by UDP or TCP to the application via the *chnl_callback* node.

- **punt_kernel** is the node to send packets to the kernel to be processed if the packet is not being processed by the application.

  - Sending these packets to the kernel allows other processes waiting for packets on standard linux sockets to process the packets.

- **arp_request** is the node used to send packets to the Linux kernel stack if the ARP entry is not known by CNET.

  - ARP packet processing is handled by the Linux kernel and not by CNET. When the CNET stack needs a destination MAC address, and it is not known, an ARP request is sent by the Linux stack.

- **chnl_callback** is the node to callback into the application to allow for more packet data processing to continue.

  - When a channel is created a callback routine is given to allow the CNET to callback into the application to help complete the connection or data processing.

Anatomy of CNET processing
--------------------------

The anatomy of the CNET stack is complex, but most of the processing and configuration is defined by
the :ref:`Graph Library <Graph_Library>`, but a number of internal structures and designs should be understood.
One of the design details is the CNET stack uses a couple thread local variables *this_cnet* and *this_stk*
to help avoid passing these values in the APIs.

The :ref:`CNET Structure <figure_cnet_structure>` is a single global structure containing information about
all of the :ref:`Stack Structures (stk_t) <figure_cnet_stack_structure>`. Each stack instance is independent of each
other except for the needed information from the *cnet* structure. The *stk_t* structure contains information
about each graph instance, which contains a set of graph nodes for the given stack instance. Each graph instance
can contain different graph nodes. The cnet-graph example always has the same set of graph nodes in each instance.
An application could have different graph layouts for each instance of a graph, but *cnet-graph* will always
have the same set of the same graph nodes in each instance of a graph.

.. note:: For the internals of the *cnet* and *stk_t* structures refer to the *Doxygen* created API
  documentation. The *channel* APIs are also defined in the documentation.

The application uses the Channel APIs to create connections or setup listening connections similar
to the socket API. Using APIs like *channel()*, *chnl_recv()*, *chnl_send()*, *chnl_bind()*, *chnl_listen()*,
*chnl_connect()*, *chnl_open()* and *chnl_accept()* are a few of the APIs to use for creating connections. The
APIs look similar to standard *Socket* APIs.

.. _figure_cnet_stack_view:

.. figure:: img/cnet_stack_view.*

   CNET Stack High Level View

CNET Structure
^^^^^^^^^^^^^^

The CNET structure :ref:`CNET Structure <figure_cnet_structure>` contains a number of fields to describe
the information to control the CNET stack. This structure is created once for all stack instances.

.. _figure_cnet_structure:

.. code-block:: c
   :caption: CNET Structure layout

       struct cnet {
           CNE_ATOMIC(uint_fast16_t) stk_order; /**< Order of the stack initializations */
           uint16_t nb_ports;                   /**< Number of ports in the system */
           uint32_t num_chnls;                  /**< Number of channels in system */
           uint32_t num_routes;                 /**< Number of routes */
           uint32_t num_arps;                   /**< Number of ARP entries */
           uint16_t flags;                      /**< Flags */
           u_id_t chnl_uids;                    /**< UID for channel descriptor like values */
           void **chnl_descriptors;             /**< List of channel descriptors pointers */
           void *netlink_info;                  /**< Netlink information structure */
           struct stk_s **stks;                 /**< Vector list of stk_entry pointers */
           struct drv_entry **drvs;             /**< Vector list of drv_entry pointers */
           struct netif **netifs;               /**< List of active netif structures */
           struct cne_mempool *rt4_obj;         /**< Route IPv4 table pointer */
           struct cne_mempool *arp_obj;         /**< ARP object structures */
           struct fib_info *rt4_finfo;          /**< Pointer to the IPv4 FIB information structure */
           struct fib_info *arp_finfo;          /**< ARP FIB table pointer */
           struct fib_info *pcb_finfo;          /**< PCB FIB table pointer */
           struct fib_info *tcb_finfo;          /**< TCB FIB table pointer */
       } __cne_cache_aligned;

The **netlink_info** is the opaque pointer to the *Netlink* information and is used with the *netlink*
library to manage the messages from the kernel. The next set of entries *nb_ports*, *num_chnls*,
*num_routes* and *num_arps* are values set at startup time to define and limit the
number of items created.

  - **nb_ports** defines the number of ports assigned to the application for the stack to use.
  - **num_chnls** defines the number of channel structures allowed in the stack.
  - **num_routes** defines the number of routes structures allowed in the stack.
  - **num_arps** defines the number of ARP structures allowed in the stack.

The **flags** field defines a simple set of flags that can be used by the stack. The two currently
defined are *CNET_PUNT_ENABLED* and *CNET_TCP_ENABLED* to control if we support punting packets to the
Linux kernel stack and if TCP support has been enabled. These flags are setup enabled/disabled in the
*meson_options.txt* file.

The **chnl_uids** (i.e., UIDs) is the bitmap to alloc/free channel descriptor values, similar to
file descriptors in Linux and other systems. The channel descriptor value is a number between 0 to N.
When a channel is created a channel descriptor is allocated and used by the application to identify
the opened channel. The channel APIs use the channel descriptor.

The **chnl_descriptors** is a list of all current channels and used to locate/translate the channel descriptor
values to a chnl structure pointer. The lookup table is global per CNET application. The **stk_order** is an
atomic variable to help in initialization of each stack instance in a specific order 0 - N. The **stks** is
the list of pointers to each stack instance. The **drvs** is the list of driver instances used by the
CNET stack. The **netifs** is the list of network interfaces attached to the CNET stack i.e, netdev or
system network interfaces.

The **rt4_obj** and **arp_obj** are mempools holding the number of IPv4 route structures and ARP structures
to enable allocating/freeing these entries quickly, plus limiting the number of each item. The *fib*
entries rt4, arp, pcb and tcb are used to locate these entries quickly using the *FIB* LPM library.

CNET Stack Structure
^^^^^^^^^^^^^^^^^^^^

The :ref:`CNET stack structure <figure_cnet_stack_structure>` is created one per thread and graph node set.
The structure contains many values and information about the given instance it defines.

.. _figure_cnet_stack_structure:

.. code-block:: c
   :caption: CNET Stack Structure layout

       typedef struct stk_s {
           pthread_mutex_t mutex;              /**< Stack Mutex */
           uint16_t idx;                       /**< Index number of stack instance */
           uint16_t lid;                       /**< lcore ID for the stack instance */
           uint16_t reserved;                  /**< Reserved for future use */
           pid_t tid;                          /**< Thread process id */
           char name[32];                      /**< Name of the network instance */
           struct cne_graph *graph;            /**< Graph structure pointer for this instance */
           struct cne_node *tx_node;           /**< TX node pointer used for sending packets */
           bitstr_t *tcbs;                     /**< Bitmap of active TCB structures based on mempool index */
           uint32_t tcp_now;                   /**< TCP now timer tick on slow timeout */
           uint32_t gflags;                    /**< Global flags */
           uint64_t ticks;                     /**< Number of ticks from start */
           mempool_t *tcb_objs;                /**< List of free TCB structures */
           mempool_t *seg_objs;                /**< List of free Segment structures */
           mempool_t *pcb_objs;                /**< PCB cnet_objpool pointer */
           mempool_t *chnl_objs;               /**< Channel cnet_objpool pointer */
           struct protosw_entry **protosw_vec; /**< protosw vector entries */
           struct icmp_entry *icmp;            /**< ICMP information */
           struct icmp6_entry *icmp6;          /**< ICMP6 information */
           struct ipv4_entry *ipv4;            /**< IPv4 information */
           struct ipv6_entry *ipv6;            /**< IPv6 information */
           struct tcp_entry *tcp;              /**< TCP information */
           struct raw_entry *raw;              /**< Raw information */
           struct udp_entry *udp;              /**< UDP information */
           struct chnl_optsw **chnlopt;        /**< Channel Option pointers */
           struct cne_timer tcp_timer;         /**< TCP Timer structure */
           struct tcp_stats *tcp_stats;        /**< TCP statistics */
       } stk_t __cne_cache_aligned;

The **name** field is the name of the stack instance, which is unique in the system. The **graph** pointer
is the pointer to the Graph instance. The **tx_node** is the output graph node to be able to send transmit
traffic to the transmit node. When needing to send packets from the application or protocol the pointer
gives access to the graph node to enqueue the data packets.

The **chnls** linked list is used to keep track of allocate and create channel structures. The CNET stack needs
to be able to locate channel structures, which come and go while the stack is running. The **tcbs** is also
a linked list of *TCB* structures to locate for processing (TCP Control Block).

The **tcbs** bitmap keeps track of the active TCB structures mainly used to dump out the set of active TCBs
using the object index into the mempool as the bitmap index value. The **tcb_objs**, **seg_objs** **pcb_objs**
and **chnl_objs** mempool structure are used to allocate and free these object quickly.

The protocol specific structure pointers (i.e., **icmp**, **ipv4**, **udp**, **tcp**, ...) hold the protocol
specific information. These entries are created as each protocol is initialized. The TCP protocol requires
a timer to manage connections. The **tcp_timer** pointer is the *cne_timer* structure pointer handling
stack timeouts. The last entry **tcp_stats** is the TCP specific statistics, which are always collected.

CNET Channel Structure
^^^^^^^^^^^^^^^^^^^^^^

The :ref:`CNET Chnl structure <figure_cnet_chnl_structure>` is created for passive and active open connections.
The structure is used to manage the connection plus store the data connected to the channel.

.. _figure_cnet_chnl_structure:

.. code-block:: c
   :caption: CNET Channel Structure layout

       struct chnl {
           uint16_t stk_id;                /**< Stack instance ID value */
           uint16_t ch_options;            /**< Options for channel */
           uint16_t ch_state;              /**< Current state of channel */
           uint16_t ch_error;              /**< Error value */
           int ch_cd;                      /**< Channel descriptor index value */
           pthread_mutex_t ch_mutex;       /**< Mutex for buffer */
           struct pcb_entry *ch_pcb;       /**< Pointer to the PCB */
           struct protosw_entry *ch_proto; /**< Current proto value */
           chnl_cb_t ch_callback;          /**< Channel callback routine */
           struct cne_node *ch_node;       /**< Next Node pointer */
           struct chnl_buf ch_rcv;         /**< Receive buffer */
           struct chnl_buf ch_snd;         /**< Transmit buffer */
       };

The **chnl** structure is an internal structure to help manage and process connections for UDP and TCP protocols.
Each chnl structure is allocated and attached to a stack instance and not shared between threads/stack instances.

The **stk_id** is used to denote which stack structure the **chnl** structure is associated with. The
**ch_options** is a bit field of values to a channel instanace. The some of the flags are *SO_BROADCAST*,
*SO_REUSEADDR*, *SO_REUSEPORT* and some others. The **ch_state** is the current state of channel, which
includes *ISCONNECTED*, *ISCONNECTING*, *_ISDISCONNECTING* and other internal flags. The **ch_error** value is
the error that occured previously and was not reported. The value is then reported in other calls or request in
the *chnl_opt_get** request. The **ch_cd** is the channel descriptor associated with this channel structure.

The **ch_pcb** is the PCB (Process Control Block) attached to this channel structure. The *PCB* structure will
be defined :ref:`Process Control Block <figure_pcb_structure>`. The **ch_proto** structure contains a number
of function pointers to connect the channel with the protocol specific protocol routines.

The **ch_callback** is the function pointer to the application function defined in the *channel* API. The
callback function is called for receiving data and helping inform the application about connections coming
and going. The primary reason for callback is receiving packet data needs to be handled in the thread context
as the stack instance to help eliminate the need for some types of locking.

The **ch_node** is the node associated with the transmit channel structure or the next node to allow the
application thread to enqueue packet data into a given CNET graph instance. The **ch_rcv** and **ch_snd** are
used to receive and send data to/from the application.

The :ref:`CNET Chnl Buffer structure <figure_cnet_chnl_buffer>` is part of the Chnl structure and manages the
channel data.

.. _figure_cnet_chnl_buffer:

.. code-block:: c
   :caption: CNET Channel Buffer layout

       struct chnl_buf {
           pktmbuf_t **cb_vec;     /**< Vector of mbuf pointers */
           uint32_t cb_cc;         /**< actual chars in buffer */
           uint32_t cb_hiwat;      /**< high water mark */
           uint32_t cb_lowat;      /**< low water mark */
           uint32_t cb_size;       /**< protocol send/receive size */
       };

Protocol Control Block (PCB)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The *PCB* structure contains information about the protocol connection and which network interface is connected
to the given instance of a connection. The *PCB* is used by the protocol packet handling to locate an active
connection as in a listening connection.

.. _figure_pcb_structure:

.. code-block:: c
   :caption: CNET Protocol Control Block

       struct pcb_key {
           struct in_caddr faddr; /**< foreign IP address */
           struct in_caddr laddr; /**< local IP address */
       } __cne_aligned(sizeof(void *));

       struct pcb_entry {
           TAILQ_ENTRY(pcb_entry) next; /**< Pointer to the next pcb_entry in a list */
           struct pcb_key key;          /**< Key values for PCB entry */
           struct netif *netif;         /**< Netif pointer */
           struct chnl *ch;             /**< Channel pointer */
           struct tcb_entry *tcb;       /**< TCB pointer */
           uint16_t opt_flag;           /**< Option flags */
           uint8_t ttl;                 /**< Time to live */
           uint8_t tos;                 /**< TOS value */
           uint8_t closed;              /**< Closed flag */
           uint8_t ip_proto;            /**< IP protocol number */
       } __cne_cache_aligned;

The **pcb_key** structure defines the local and foreign addresses (note: it currently only handles IPv4
addresses), which define a connection and is how the connection is found by the protocol processing.
The **next** structure is a linked list of *PCBs* attached to *half open* or *backlog* queues for
application/protocols to locate an active *PCBs*.
