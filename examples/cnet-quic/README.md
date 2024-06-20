# Testing Quicly stack with CNDP CNET stack

## Overview

The example application links with the quicly stack to provide a simple PoC for
QUIC and the CNET UDP stack. The packets are copied from/to quicly library and
will effect performance, but the goal is to see if CNET interoperates with a
QUIC stack.

The CNET stack is collecting and processing UDP frames for a given UDP
destination port address 4433. The normal port address for QUIC is 433, but for
this test we are going to use 4433 instead.

Use two machines to make it easy to setup and configure, plus connect the
machines back to back with a cable.

## Remote machine setup, this machine will not run CNDP, but use the quicly example applications

Setup the interface connected to the other machine, use your own netdev
interface name

```console
% sudo ifconfig ens260f0 198.18.0.3/24 up
```

## Local machine setup, this machine will run CNDP/CNET/quicly

```console
% sudo apt install libssl-dev

% git clone https://github.com/h2o/quicly

% cd quicly
% git submodule update --init --recursive
% cmake .
% make
```

> Note: Plus read the quicly/README.md file for more information. Clone and
> build picotls

```console
% git clone https://github.com/h2o/picotls

% git submodule init
% git submodule update
```

> Build using cmake:

```console
% cmake .
% make
```

> Plus read the picotls/README.md file for more information. Clone CNDP and
> build it.

```console
% cd cndp
% vi meson_options.txt
```

Edit the two options quicly_path and picotls_path to point to quickly and
picotls directories. The paths must be absolute paths.

CNDP should find the quicly and picotls directories along with the libraries
needed to build the the example in CNDP.

```console
% make rebuild-install
```

## Running CNDP example

Edit the cndp/examples/quic.jsonc file to add your interfaces and other machine
specific information.

```console
% cd cndp
% sudo ifconfig enp94s0f0 198.18.0.2/24 up
% sudo ethtool -N enp94s0f0 flow-type udp4 action 11  # must match the qid in the jsonc file.
%
% ./tools/rcndp cnet-quic -c examples/cnet-quic/quic.jsonc -- -c examples/cnet-quic/server.crt \
   -k examples/cnet-quic/server.key 192.168.0.2 4433
```

```console
Startup output look something like this:
*** quic-echo, PID: 57482 lcore: 10
(initialize_graph        : 110) INFO: Graph Name: 'cnet_1'
Punt     TUN name: 'punt0       ' fd 13 Multi-queue: 16 queues

** Version: CNDP 21.09.1, Command Line Interface
CNDP-cli:/>
```

A number of commands are available at the CLI prompt.

```console
CNDP-cli:/> ls      # list the current directory cnet and sbin contain commands
CNDP-cli:/> route   # display the current routing table
CNDP-cli:/> arp     # display the current ARP table from the host
CNDP-cli:/> ifs     # display the current interfaces configured for CNET
CNDP-cli:/> pcb     # display the current Protocol Control Block information
```

## Quick test using quicly/cli command

```console
% ./cli 198.18.0.2 4433  # 198.18.0.2 is the CNDP interface address.

packets-received: 5, packets-decryption-failed: 0, packets-sent: 3, packets-lost: 0, ack-received: 2, late-acked: 0, bytes-received: 1760, bytes-sent: 1417, srtt: 1

% ./cli -p /main.jpg 198.18.0.2 4433 # will grep the assets/main.jpg file and dump to stdout.
``

The command will contact the quicly stack on the other machine and report back complete or transfer the requested file.
```
