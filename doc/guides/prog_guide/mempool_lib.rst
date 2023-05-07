..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2010-2023 Intel Corporation.

.. _Mempool_Library:

Mempool Library
===============

A memory pool is an allocator of a fixed-sized objects. In the CNDP, it is identified by name and uses a mempool handler to store free objects.
The default mempool handler is ring based. It provides some other optional services such as a per-core object cache and
an alignment helper to ensure that objects are padded to spread them equally on all DRAM or DDR3 channels.

This library is used by the :ref:`Pktmbuf Library <Pktmbuf_Library>`.

When creating a new pool, the user can specify to use this feature or not.

.. _mempool_local_cache:

Local Cache
-----------
To avoid having too many access requests to the memory pool's ring, the memory pool allocator can maintain a per-thread cache and do bulk requests to the memory pool's ring, via the cache with many fewer locks on the actual memory pool structure.
In this way, each thread has full access to its own cache (with locks) of free objects and
only when the cache fills does the core need to shuffle some of the free objects back to the pools ring or obtain more objects when the cache is empty.

While this may mean a number of buffers may sit idle on some thread's cache, the speed at which a core can access its own cache for a specific memory pool without locks provides performance gains.

The cache is composed of a small, per-thread table of pointers and its length (used as a stack).
This internal cache can be enabled or disabled at creation of the pool.

:numref:`figure_mempool` shows a cache in operation.

.. _figure_mempool:

.. figure:: img/mempool.*

   Mempool

Use Cases
---------

All allocations that require a high level of performance should use a pool-based memory allocator.
Below are some examples:

*   :ref:`Pktmbuf Library <Pktmbuf_Library>`

*   Any application that needs to allocate fixed-sized objects in the data plane and that will be continuously utilized by the system.
