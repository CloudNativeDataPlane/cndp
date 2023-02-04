..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2010-2023 Intel Corporation.

Introduction
============

This document is a user guide for the ``test-cne`` test application shipped as part of CNDP.

The ``test-cne`` application is used to test the CNDP libraries. It's essentially a functional test
harness.

Running the Application
=======================

After :ref:`building CNDP <building-cndp>`, run ``test-cne`` with the following command.

.. code-block:: console

  sudo ./builddir/test/testcne/test-cne

The example below shows how to run a specific test:

.. code-block:: console

  sudo ./builddir/test/testcne/test-cne -- mempool
  >>>> Mempool tests: Lcore ID 52, Socket ID 0
    ** PASS - TEST: 0: mempool cnt  1024, sz   512, cache_size     0

    ** PASS - TEST: PASS --- TEST: Mempool obj count test pass

    ** PASS - TEST: PASS --- TEST: Mempool empty status test pass

    ** PASS - TEST: PASS --- TEST: Mempool full status test pass

    ** PASS - TEST: 1: mempool cnt  2048, sz  1024, cache_size    64

    ** PASS - TEST: PASS --- TEST: Mempool obj count test pass

    ** PASS - TEST: PASS --- TEST: Mempool empty status test pass

    ** PASS - TEST: PASS --- TEST: Mempool full status test pass

    ** PASS - TEST: 2: mempool cnt  2048, sz  1024, cache_size    64

    ** PASS - TEST: PASS --- TEST: Mempool obj count test pass

    ** PASS - TEST: PASS --- TEST: Mempool empty status test pass

    ** PASS - TEST: PASS --- TEST: Mempool full status test pass

    ** PASS - TEST: 3: mempool cnt  4096, sz  2048, cache_size   128

    ** PASS - TEST: PASS --- TEST: Mempool obj count test pass

    ** PASS - TEST: PASS --- TEST: Mempool empty status test pass

    ** PASS - TEST: PASS --- TEST: Mempool full status test pass

  <<<< Mempool Tests: done.


Testcne Command-line Options
----------------------------

Use 'chelp -a' to list all commands

.. code-block:: console

  *** All executable commands in path ***
  /:
  sbin:
    version          Display version information
    echo             simple echo a string to the screen
    script           load and process cli command files
    env              Show/del/get/set environment variables
    path             display the execution path for commands
    hugepages        hugepages # display hugepage info
    cmap             cmap # display the core mapping
    more             more <file> # display a file content
    history          history # display the current history
    exit             exit # quit the application
    q                q # quit the application
    quit             quit # quit the application
    screen.clear     screen.clear # clear the screen
    pwd              pwd # display current working directory
    cd               cd <dir> # change working directory
    ls               ls  <dir> # list current directory
    rm               remove a file or directory
    mkdir            create a directory
    ?                CLI help - display information for CNDP
    chelp            CLI help - display information for CNDP
    sleep            delay a number of seconds
    delay            delay a number of milliseconds
  bin:
    xskdev           Run the xskdev API test
    uid              Run the User ID Allocator test
    timer            Run the Timer test
    thread           Run the Thread test
    sizeof           Size of structures
    ring             Run RING test
    ring_profile     Run RING profile test
    ring_api         Run RING api tests
    pktdev           Run the pktdev tests
    pktcpy           Run pktcpy test
    pkt              Run PKT test
    mmap             Run MMAP test
    mempool          Run MEMPOOL test
    mbuf             Run MBUF test
    loop             Port loop test
    kvargs           Run the KVARGS tests
    jcfg             Run the JSON CFG file tests
    ibroker          Run the ibroker tests
    hmap             Run the HashMap CFG file tests
    hash             Run the hash test
    hash_perf        Run the hash perf test
    graph            Run the graph test
    graph_perf       Run the graph perf test
    dsa              Run the dsa API test
    cthread          Run the cthread API test
    all              Run all tests
    acl              Run the ACL tests
