..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2010-2022 Intel Corporation.

Glossary
========

API
   Application Programming Interface

BSD
   Berkeley Software Distribution

CNDP
   Cloud Native Data Plane.

Control Plane
   The control plane is concerned with the routing of packets and with
   providing a start or end point.

Core
   A core may include several lcores or threads if the processor supports
   hyperthreading.

Core Components
   A set of libraries provided by the CNDP, ring, mempool, pktmbuf and so on.

CPU
   Central Processing Unit

Data Plane
   In contrast to the control plane, the data plane in a network architecture
   are the layers involved when forwarding packets.  These layers must be
   highly optimized to achieve good performance.

DIMM
   Dual In-line Memory Module

Doxygen
   A documentation generator used in the CNDP to generate the API reference.

DRAM
   Dynamic Random Access Memory

DSA
   Data Streaming Accelerator

FIFO
   First In First Out

FPGA
   Field Programmable Gate Array

HW
   Hardware

ID
   Identifier

IOCTL
   Input/Output Control

I/O
   Input/Output

IP
   Internet Protocol

IPv4
   Internet Protocol version 4

IPv6
   Internet Protocol version 6

L1
   Layer 1

L2
   Layer 2

L3
   Layer 3

L4
   Layer 4

LAN
   Local Area Network

LPM
   Longest Prefix Match


MTU
   Maximum Transfer Unit

NIC
   Network Interface Card

OOO
   Out Of Order (execution of instructions within the CPU pipeline)

NUMA
   Non-uniform Memory Access

PCI
   Peripheral Connect Interface

PHY
   An abbreviation for the physical layer of the OSI model.

pktmbuf
   A pktmbuf is a data structure used internally to carry messages (mainly
   network packets).  The name is derived from BSD stacks.  To understand the
   concepts of packet buffers or pktmbuf, refer to *TCP/IP Illustrated, Volume 2:
   The Implementation*.

PMD
   Poll Mode Driver

QoS
   Quality of Service

RCU
   Read-Copy-Update algorithm, an alternative to simple rwlocks.

Rd
   Read

RED
   Random Early Detection

RSS
   Receive Side Scaling

Rx
   Reception

SLA
   Service Level Agreement

srTCM
   Single Rate Three Color Marking

SRTD
   Scheduler Round Trip Delay

SW
   Software

Target
   In the CNDP, the target is a combination of architecture, machine,
   executive environment and toolchain.  For example:
   i686-native-linux-gcc.

TCP
   Transmission Control Protocol

TC
   Traffic Class

TLB
   Translation Lookaside Buffer

TLS
   Thread Local Storage

trTCM
   Two Rate Three Color Marking

TSC
   Time Stamp Counter

Tx
   Transmission

TUN/TAP
   TUN and TAP are virtual network kernel devices.

VLAN
   Virtual Local Area Network

Wr
   Write

WRED
   Weighted Random Early Detection

WRR
   Weighted Round Robin
