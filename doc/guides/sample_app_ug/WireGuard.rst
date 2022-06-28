..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2019-2022 Intel Corporation.

Wireguard Rust user space
=========================

.. _Wireguard_overview:

WireGuard
----------

WireGuard is an extremely simple yet fast and modern VPN that uses state-of-the-art cryptography.
Wireguard Rust is a user space implementation of the wireguard protocol. It's maintained in GitHub
at `wireguard-rs <https://github.com/WireGuard/wireguard-rs/>`_.


WireGuard Rust user space with CNDP
-----------------------------------

Wireguard Rust user space implementation uses CNDP/AF-XDP to send and receive packets from/to user
space CNDP/AF-XDP replaces existing linux networking stack used to send/receive WireGuard UDP
packets. Wireguard Rust with CNDP will run on Linux platform. WireGuard CNDP application runs as a
background process and by default uses WireGuard kernel TUN interface to read/write packets from TUN
interface. It uses CNDP API's to send and receive UDP packets.

.. _Wireguard_CNDP_custom_app:

A custom linux application is also implemented on top of Wireguard and CNDP stack which uses Rust
channel instead of Kernel TUN interface for data path. Control path still uses Kernel TUN interface
to configure local and peer encryption keys, ip addresses, peer end point etc.

.. figure:: img/WG_CNDP.png

.. figure:: img/WG_CNDP_Custom_app.png


WireGuard Rust High level flow
-------------------------------

High level flow of Wireguard Rust is shown in below diagram. Here UDP reader and writer uses CNDP
APIs to receive and send WireGuard UDP packets.

.. figure:: img/WG_RUST_HighLevelFlow.png


Wireguard CNDP performance measurement setup using DPDK PktGen
---------------------------------------------------------------

Flow traffic configuration setup which is used to measure Wireguard CNDP performance is shown in
below diagram. This uses custom Wireguard CNDP application described in
:ref:`Custom Wireguard <Wireguard_CNDP_custom_app>`

.. figure:: img/WG_CNDP_Traffic_Flow.png


Setup WireGuard Rust with CNDP
------------------------------

Clone the Wireguard Rust repo and checkout the commit on which the patches are based:

.. code-block:: console

  git clone https://github.com/WireGuard/wireguard-rs.git
  cd wireguard-rs
  git checkout 7d84ef9

Apply the Wireguard CNDP patches in lang/rs/wireguard/patch. Ignore the whitespace warning errors.

.. code-block:: console

  git am *.patch

Build Wireguard with CNDP

.. code-block:: console

  cargo build --release

In Wireguard repo, refer to src/platform/linux/cndp/README.md file under usage section to configure
and start Wireguard with CNDP.


Future work
-----------
Currently network I/O performance in WireGuard Rust is optimized by using CNDP/AF-XDP. There are
other opportunities for performance optimization like chacha20-poly1305 encryption/decryption, using
lockless queue implementation (using DLB or lockless ring).
