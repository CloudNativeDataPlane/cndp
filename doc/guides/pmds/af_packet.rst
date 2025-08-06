..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2019-2025 Intel Corporation.

AF_PACKET Poll Mode Driver
==========================

The AF_PACKET socket in Linux allows an application to receive and send raw
packets. This Linux-specific PMD driver binds to an AF_PACKET socket and
allows a CNDP application to send and receive raw packets through the Kernel.

In order to improve Rx and Tx performance this implementation makes use of
PACKET_MMAP, which provides a mmap’ed ring buffer, shared between user space
and kernel, that’s used to send and receive packets. This helps reducing system
calls and the copies needed between user space and Kernel.

Since this implementation is based on PACKET_MMAP, and PACKET_MMAP has its own
pre-requisites, it should be noted that the inner workings of PACKET_MMAP should
be carefully considered. PACKET_MMAP expects each single “frame” to fit inside of
a “block”. And although multiple “frames” can fit inside of a single “block”,
a “frame” may not span across two “blocks”.

For the full details behind PACKET_MMAP’s structures and settings, consider
reading `PACKET_MMAP documentation in the Kernel
<https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt>`_.


Prerequisites
-------------

This is a Linux-specific PMD, thus the following prerequisites apply:

*  A Linux Kernel;
*  A Kernel bound interface to attach to (e.g. a tun/tap interface);
