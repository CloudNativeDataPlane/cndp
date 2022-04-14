..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2018-2019 Cisco Systems, Inc.
    Copyright (c) 2020-2022 Intel Corporation.

======================
Memif Poll Mode Driver
======================

Shared memory packet interface (memif) PMD allows for CNDP and any other client
using memif (DPDK, VPP, libmemif) to communicate using shared memory. Memif is
Linux only.

The created device transmits packets in a raw format. It can be used with
Ethernet mode, IP mode, or Punt/Inject. At this moment, only Ethernet mode is
supported in CNDP memif implementation.

Memif works in two roles: server and client. Client connects to server over an
existing socket. It is also a producer of shared memory file and initializes
the shared memory. Each interface can be connected to one peer interface
at same time. Server creates the socket and listens for any client connection
requests. The socket may already exist on the system. Be sure to remove any such
sockets, if you are creating a server interface, or you will see an
"Address already in use" error.

The method to enable one or more interfaces is to use the json file configuration
by adding client or server to the lport configuration. Memif uses unix domain socket
to transmit control messages.

**Connection establishment**

In order to create memif connection, two memif interfaces, each in separate
process, are needed. One interface in ``server`` role and other in
``client`` role. It is not possible to connect two interfaces in a single
process. Each interface can be connected to one interface at same time,
identified by matching id parameter.

Memif driver uses unix domain socket to exchange required information between
memif interfaces. If socket is used by ``server`` interface, it's marked as
listener socket (in scope of current process) and listens to connection requests
from other processes. One socket can be used by multiple interfaces. One process
can have ``client`` and ``server`` interfaces at the same time, provided each role
is assigned unique socket.

For detailed information on memif control messages, see: net/memif/memif.h.

Client interface attempts to make a connection on assigned socket. Process
listening on this socket will extract the connection request and create a new
connected socket (control channel). Then it sends the 'hello' message
(``MEMIF_MSG_TYPE_HELLO``), containing configuration boundaries. Client interface
adjusts its configuration accordingly, and sends 'init' message
(``MEMIF_MSG_TYPE_INIT``). This message among others contains interface id. Driver
uses this id to find server interface, and assigns the control channel to this
interface. If such interface is found, 'ack' message (``MEMIF_MSG_TYPE_ACK``) is
sent. Client interface sends 'add region' message (``MEMIF_MSG_TYPE_ADD_REGION``) for
every region allocated. Server responds to each of these messages with 'ack'
message. Same behavior applies to rings. Client sends 'add ring' message
(``MEMIF_MSG_TYPE_ADD_RING``) for every initialized ring. Server again responds to
each message with 'ack' message. To finalize the connection, client interface
sends 'connect' message (``MEMIF_MSG_TYPE_CONNECT``). Upon receiving this message
server maps regions to its address space, initializes rings and responds with
'connected' message (``MEMIF_MSG_TYPE_CONNECTED``). Disconnect
(``MEMIF_MSG_TYPE_DISCONNECT``) can be sent by both server and client interfaces at
any time, due to driver error or if the interface is being deleted.

Files

- net/memif/memif.h *- control messages definitions*
- net/memif/memif_socket.h
- net/memif/memif_socket.c

Shared memory
~~~~~~~~~~~~~

**Shared memory format**

Client is producer and server is consumer. Memory regions, are mapped shared memory files,
created by memif client and provided to server at connection establishment.
Regions contain rings and buffers. Rings and buffers can also be separated into multiple
regions. For no-zero-copy, rings and buffers are stored inside single memory
region to reduce the number of opened files.

region n (no-zero-copy):

+-----------------------+-------------------------------------------------------------------------+
| Rings                 | Buffers                                                                 |
+-----------+-----------+-----------------+---+---------------------------------------------------+
| S2M rings | M2S rings | packet buffer 0 | . | pb ((1 << pmd->run.log2_ring_size)*(s2m + m2s))-1 |
+-----------+-----------+-----------------+---+---------------------------------------------------+

S2M OR M2S Rings:

+--------+--------+-----------------------+
| ring 0 | ring 1 | ring num_s2m_rings - 1|
+--------+--------+-----------------------+

ring 0:

+-------------+---------------------------------------+
| ring header | (1 << pmd->run.log2_ring_size) * desc |
+-------------+---------------------------------------+

Descriptors are assigned packet buffers in order of rings creation. If we have one ring
in each direction and ring size is 1024, then first 1024 buffers will belong to S2M ring and
last 1024 will belong to M2S ring. In case of zero-copy, buffers are dequeued and
enqueued as needed.

**Descriptor format**

+----+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Quad|6| | | | | | | | | | | | | | | | | | | | | | | | | | | | | | |3|3| | | | | | | | | | | | | | |1|1| | | | | | | | | | | | | | | |
|    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Word|3| | | | | | | | | | | | | | | | | | | | | | | | | | | | | | |2|1| | | | | | | | | | | | | | |6|5| | | | | | | | | | | | | | |0|
+----+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0   |length                                                         |region                         |flags                          |
+----+---------------------------------------------------------------+-------------------------------+-------------------------------+
|1   |metadata                                                       |offset                                                         |
+----+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    |6| | | | | | | | | | | | | | | | | | | | | | | | | | | | | | |3|3| | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | |
|    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    |3| | | | | | | | | | | | | | | | | | | | | | | | | | | | | | |2|1| | | | | | | | | | | | | | | | | | | | | | | | | | | | | | |0|
+----+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

**Flags field - flags (Quad Word 0, bits 0:15)**

+-----+--------------------+------------------------------------------------------------------------------------------------+
|Bits |Name                |Functionality                                                                                   |
+=====+====================+================================================================================================+
|0    |MEMIF_DESC_FLAG_NEXT|Is chained buffer. When set, the packet is divided into multiple buffers. May not be contiguous.|
+-----+--------------------+------------------------------------------------------------------------------------------------+

**Region index - region (Quad Word 0, 16:31)**

Index of memory region, the buffer is located in.

**Data length - length (Quad Word 0, 32:63)**

Length of transmitted/received data.

**Data Offset - offset (Quad Word 1, 0:31)**

Data start offset from memory region address. *.regions[desc->region].addr + desc->offset*

**Metadata - metadata (Quad Word 1, 32:63)**

Buffer metadata.

Files

- net/memif/memif.h *- descriptor and ring definitions*
- net/memif/pmd_memif_socket.c *- pmd_memif_socket_rx() pmd_memif_socket_tx()*

**Shared memory format**

Region 0 is created by memif driver and contains rings. Client interface exposes CNDP memory (mmap or malloc).
Instead of using memfd_create() to create new shared file, existing memory segment or mmap region is created an used.

region 0:

+-----------------------+
| Rings                 |
+-----------+-----------+
| S2M rings | M2S rings |
+-----------+-----------+

region n:

+-----------------+
| Buffers         |
+-----------------+
| pktmbufs or     |
| raw buffers     |
+-----------------+

Buffers are dequeued and enqueued as needed. Offset descriptor field is calculated at tx.

