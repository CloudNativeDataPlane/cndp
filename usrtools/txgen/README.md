# TXGen - Traffic Generator powered by CNDP

=====================================================

**TXGen is a traffic generator powered by CNDP at wire rate traffic with 64 byte frames.**

## (TXGen) Sounds like 'Packet-Gen'

---

```console
SPDX-License-Identifier: BSD-3-Clause
Copyright (c) 2019-2023 Intel Corporation.
```

---

## TXGen command line directory format ***

```console
    -- TXGen Ver: 20.11.0 (CNDP 20.11.0)  Powered by CNDP ---------------

    TXGen:/> ls
    [txgen]        [sbin]          copyright
    TXGen:/> ls txgen/bin
    off             on              debug           set
    stp             str             stop            start           disable
    enable          theme           page
    lport            restart         rst
    reset           cls             redisplay       save
    script          load            clr
    clear.stats     help
    TXGen:/>

-------------------------------------------------------------------------------

    TXGen:/> ls
    [txgen]        [sbin]          copyright
    TXGen:/> ls sbin
    env             dbg             path            hugepages       cmap
    sizes           more            history         quit            clear
    pwd             cd              ls              rm              mkdir
    chelp           sleep           delay
    TXGen:/>

-------------------------------------------------------------------------------

    TXGen:/> cd sbin
    TXGen:/sbin/>
    TXGen:/sbin/> ls -l
       env              Command : Set up environment variables
       path             Command : display the command path list
       hugepages        Command : hugepages # display hugepage info
       cmap             Command : cmap # display the core mapping
       sizes            Command : sizes # display some internal sizes
       more             Command : more <file> # display a file content
       history          Command : history # display the current history
       quit             Command : quit # quit the application
       clear            Command : clear # clear the screen
       pwd              Command : pwd # display current working directory
       cd               Command : cd <dir> # change working directory
       ls               Command : ls [-lr] <dir> # list current directory
       rm               Command : remove a file or directory
       mkdir            Command : create a directory
       chelp            Command : CLI help - display information for CNDP
       sleep            Command : delay a number of seconds
       delay            Command : delay a number of milliseconds

    TXGen:/sbin/>
    TXGen:/sbin/> cd ..
    TXGen:/>

-------------------------------------------------------------------------------

    TXGen:/txgen/> cd bin
    TXGen:/txgen/bin/> ls -l
       off              Alias : disable screen
       on               Alias : enable screen
       set              Command : set a number of options
       stp              Alias : stop all
       str              Alias : start all
       stop             Command : stop features
       start            Command : start features
       disable          Command : disable features
       enable           Command : enable features
       theme            Command : Set, save, show the theme
       page             Command : change page displays
       restart          Command : restart lport
       rst              Alias : reset all
       reset            Command : reset txgen configuration
       cls              Alias : redisplay
       redisplay        Command : redisplay the screen
       save             Command : save the current state
       load             Command : load command file
       clr              Alias : clear.stats all
       clear.stats      Command : clear stats
       help             Command : help command

    TXGen:/txgen/bin/>

===== Application Usage =====

Usage: ./builddir/txgen/app [-h] [-c json_file]
           -c <json-file> The JSON configuration file
           -C             Wait on unix domain socket for JSON or JSON-C file
           -d             More debug stats are displayed
           -h             Display the help information

```

## Building TXGen
TXgGen is built by default when CNDP is built

## Running TXGen
Running TXGen is similar to running any of the applications.

1. Start with the provided txgen.json.c and modify it to include appropriate configurations: such as interface names...

NOTE: that the threads roles for TXGen are different to thread roles from the simple examples.

2. Create appropriate ethtool filters if you plan on Receiving Traffic.

3. Run the TXGen application
