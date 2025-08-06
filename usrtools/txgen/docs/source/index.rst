..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2019-2025 Intel Corporation.

The TXGen Application
======================

**TXGen**, (*Packet* *Gen*-erator) is a software based traffic generator
powered by the CNDP fast packet processing framework.

Some of the features of TXGen are:

* It is capable of generating 10Gbit wire rate traffic with 64 byte frames.
* It can act as a transmitter or receiver at line rate.
* It has a runtime environment to configure, and start and stop traffic flows.
* It can display real time metrics for a number of lports.
* It can generate packets in sequence by iterating source or destination MAC,
  IP addresses or lports.
* It can handle packets with UDP, TCP, ARP, ICMP, GRE, MPLS and
  Queue-in-Queue.
* It can be controlled remotely over a TCP connection.
* It is configurable via Lua and can run command scripts to set up repeatable
  test cases.
* The software is fully available under a BSD licence.


TXGen was created 2020 @ intel.com

.. only:: html

   See the sections below for more details.

   Contents:


.. toctree::
   :maxdepth: 1

   getting_started.rst
   running.rst
   commands.rst
   copyright.rst
   license.rst
