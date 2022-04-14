# Example CNDP VPP plugin

## Overview

The "cndp" directory contains code which should be copied to src/plugins within
the VPP software repo. Before building the plugin, you should ensure that CNDP
is installed in a location which is searched by the compiler/linker. Do this
by building CNDP normally, then install with "sudo CNE_DEST_DIR=/ make install".

## Known limitations

The plugin works with VPP version 21.01 and will not compile on newer versions.

The max number of devices supported right now is 6. This can be increased by
increasing #define CNDP_MAX_DEVS 6 in cndp.h

The max number of queues that can be configured for the single threaded
VPP implementation is 30, this is hard coded in cndp.h and can be changed.

If using multiple workers with the CNDP plugin there are a few limitations:
- The number of threads must match the number of queues.
- The max number of threads/queues supported is 4.

These queue limitations are related to the number of buffers supported in VPP.
To support more lports make sure to configure the number of buffers per NUMA in the startup.conf:

```
buffers {
          ## Increase number of buffers allocated, needed only in scenarios with
          ## large number of interfaces and worker threads. Value is per numa node.
          ## Default is 16384 (8192 if running unpriviledged)
          buffers-per-numa 128000

          ## Size of buffer data area
          ## Default is 2048
          # default data-size 2048
 }

Please also make sure to modify the #define CNDP_MAX_DEVS 6 and #define CNDP_MAX_PORTS 30
 in cndp.h file

```

## RSS configuration
Take note of what your interface is configured to use before modifying the configuration.

```
$ ethtool -x ens786f2
```
Modify the RSS configuration to feed the queues you would like to use with the CNDP plugin
```
$ ethtool -X ens786f2 equal 2 start 10
```

## Run VPP with CNDP plugin

Once CNDP is installed, grab the VPP source code, copy the plugin, and build
VPP normally, e.g.

Be sure to checkout version 21.01.

```
make install-dep
make install-ext-dep
make build-release
```

Run vpp, then create a CNDP interface using the netdev name, and assign an
IP address, e.g.

```
make run-release
vpp# create interface cndp name ens786f2 qs 1 offset 10
vpp# set interface ip address ens786f2 48.0.0.154/24
vpp# set interface state ens786f2 up
```

To trace packets through the cndp-input node, use:
```
trace add cndp-input 10
... traffic running ...
show trace
```

To set a static arp entry use:
```
set ip neighbor ens786f2 48.0.0.1 3c:fd:fe:9c:e7:22
```

To enable/disable pcap capture use:
```
pcap trace tx intfc ens786f2 file new.pcap
pcap trace off
```

## Examples startup.conf

There's an issue with a single worker threads that needs further investigation for the
configuration below. No workers or workers > 1 works fine.

A simple startup.conf would be:
```
unix {
  nodaemon
  interactive
  cli-listen /run/vpp/cli.sock
  exec /tmp/setup.txt
  gid 0
}

plugins
{
  plugin default { disable }
  plugin cndp_plugin.so { enable }
}

cpu {
        ## In the VPP there is one main thread and optionally the user can create worker(s)
        ## The main thread and worker thread(s) can be pinned to CPU core(s) manually or automatically

        ## Manual pinning of thread(s) to CPU core(s)

        ## Set logical CPU core where main thread runs, if main core is not set
        ## VPP will use core 1 if available
        # main-core 1

        ## Set logical CPU core(s) where worker threads are running
        #corelist-workers 2-3,18-19

        ## Sets number of CPU core(s) to be skipped (1 ... N-1)
        ## Skipped CPU core(s) are not used for pinning main thread and working thread(s).
        ## The main thread is automatically pinned to the first available CPU core and worker(s)
        ## are pinned to next free CPU core(s) after core assigned to main thread
        skip-cores 4

        ## Specify a number of workers to be created
        ## Workers are pinned to N consecutive CPU cores while skipping "skip-cores" CPU core(s)
        ## and main thread's CPU core
        ## NOTE: MAX number of supported workers is 4.
        ## NOTE: worker number should match the CNDP lport number if using workers.
        ## NOTE: worker configuration is optional.
        # workers 2
}
```

where setup.txt is
```
create interface cndp name ens786f2 qs 2 offset 10
set interface ip address ens786f2 48.0.0.154/24
set interface state ens786f2 up
set ip neighbor ens786f2 48.0.0.1 3c:fd:fe:9c:e7:22
```


