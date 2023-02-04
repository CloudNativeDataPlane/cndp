..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2022-2023 Intel Corporation.

.. _MsgChan_Library:

MsgChan Library
===============

The msgchan library allows the user to create a pipe like message channel in user space using the
lockless rings. The user can send and receive messages between different threads and between other
languages. One goal is to have a Go binding to allow for passing messages between Go and CNDP.

*   Uses a lockless rings in FIFO mode

*   Refer to the lockless library for more information

*   Message objects can be pointers or elements of multiple of 8 byte in size

*   Lockless implementation

*   Multi-consumer or single-consumer dequeue

*   Multi-producer or single-producer enqueue

*   Burst dequeue - Dequeue the maximum available objects if the specified count cannot be fulfilled

*   Burst enqueue - Enqueue the maximum available objects if the specified count cannot be fulfilled

The advantages of this data structure is to create a simple message channel between different
languages/threads.

*   Create a pipe like message channel in user space for easy setup and simple interfaces. Most of the advantage of this data structure come from the lockless ring implementation.

*   Handling the connections between multiple threads is managed within the msgchan code and not requiring the user to manage.

Use Cases
---------

Use cases for the MsgChan library include:

    *  Communication between application threads in CNDP

    *  Allow threads to attach to an existing msgchan, creating children message channels.

Anatomy of a MsgChan
--------------------

Creating a MsgChan is a simple call to mc_create(const char \*name, int size, uint32_t flags).
Giving the name of the channel to create or attach to as a child msgchan. The parent msgchan
is the first one to be created and any other attempts to create the message channel will create
a child msgchan if allowed.

A msgchan is identified by a unique name. It's important that the application uses unique names
or the same name string to create children msgchan's to be created.

The size value is the number of entries in the rings for communicating between threads. A entry
8 bytes in size, which is good for a pointer or you can encode data into the 8 bytes. If your
message will fit in 8 bytes.

The flags are used to define the type of lockless rings to be created, Multi-producer or
single consumer type rings. Look at the ring library to understand the flags. The flags value
also has one more flags MC_NO_CHILD_CREATE flag, which disallows a child msgchan to be created.

Using mc_send() and mc_recv() calls allows the two threads to communicate over the rings. The
parent and children of the parent share the lockless rings. If more then one child then you must
pass the correct flags value meaning values i.e. RING_F_SP_ENQ and/or RING_F_SC_DEQ. The default
configuration is multi-producer and multi-consumer ring when flags is 0. If only one child
then single-producer and single consumer (RING_F_SP_ENQ/RING_F_SP_DEQ) can be passed into the call.
