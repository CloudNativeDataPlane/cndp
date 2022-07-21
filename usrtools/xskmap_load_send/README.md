# xsk_map load and send utility

This is a simple utility that loads a pinned xsk_map fd and sends it to
a CNDP application that's configured to work in unprivileged mode. It
allows the end user to load their own custom BPF programs besides the
default AF_XDP redirect program provided by the kernel.
For e.g. https://github.com/maryamtahhan/xdp-progs/blob/main/xdp-filter-udp/xdp_prog_kern.c

> **_NOTE_** The loading is left outside the scope of CNDP as there are
many options available for use.

Running the application will create a UDS named `app_socket.{proc_id}`
in the path `/var/run/cndp/`. An example configuration for the `cndpfwd`
application to be used alongside this utility is shown below:

```json
    ...
    "lports": {
        "eno1:0": {
            "pmd": "net_af_xdp",
            "qid": 11,
            "umem": "umem0",
            "region": 0,
            "description": "LAN 0 port",
            "unprivileged": true
        }
    },
    ...
    "options": {
        "pkt_api": "xskdev",
        "no-metrics": false,
        "no-restapi": false,
        "cli": true,
        "mode": "drop",
        "uds_path": "/var/run/cndp/app_socket.580113"
    },
    ...
```

To run the application with a pinned map called xsks_map

```cmd
./xskmap_load_and_send -m /sys/fs/bpf/xsks_map
```
