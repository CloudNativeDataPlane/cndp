# Packet Distributor

A example application to distribute packets to workers.

## Explanation

This example contains 1 rx thread, 1 tx thread, and 4 worker threads.

The rx thread receives packets, and then passes one packet to a worker via
lockless ring each time.

The worker thread dequeues packets from its lockless ring and swaps packets' MAC
address, and enqueues processed packets to another lockless ring shared by all
workers.

The tx thread reads packets from the lockless ring to send.

## Config

- Configure an ethtool filter to steer packets to a specific queue.

  ```bash
  sudo ethtool -N <devname> flow-type udp4 dst-port <dport> action <qid>
  sudo ip link set dev <devname> up
  ```

- Edit `config.jsonc`, make sure the `lports` section has the same netdev name
  and queue id for which the ethtool filter is configured. Make sure the
  `threads` section has the correct `lports` configured

## Usage

```bash
An example to distribute packets via lockless rings between worker threads

Usage:
distributor -c config.jsonc [flags]

Flags:
-c, --config string path to configuration file
-h, --help help for distributor
-V, --verbose verbose output
-v, --version version for distributor
```

## Run

```bash
./run_distributor -c config.jsonc
```
