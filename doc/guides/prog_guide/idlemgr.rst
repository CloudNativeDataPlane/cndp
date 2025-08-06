..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2022-2025 Intel Corporation.

.. _Idlemgr_Library:

Idlemgr Library
===============

The idlemgr (Idle Manager) will manage threads idleness when polling lports or
any file descriptor. When idle is detected it will call epoll_wait() to wait on
RX traffic for the added file descriptors.

*   Uses epoll() groups to manage file descriptors.

*   Manages any type of file descriptors in which we need to poll.

*   Detects idleness when the application is polling and calls epoll_wait() to force the thread into idle mode.

The current design in CNDP is 100% polling of the receive ring in AF_XDP
or PMD which means burning core power. The patch adds two parameters to
the jsonc file to control polling idle_timeout and intr_timeout
in thread section.

The idlemgr library handles managing epoll and calling epoll_wait when the
idle_timeout value has been met, then it calls epoll_wait(). The idlemgr
operates on threads, using file descriptors as the method to wakeup a sleeping
thread. The caller needs to add file descriptors to the idlemgr instance and
then call idlemgr_process() with a flag if the thread thinks it is idle or
not.

The first one gives the number of milliseconds to wait for the RX ring to
be idle, then call epoll() with a timeout of intr_timeout. When no Rx traffic
for a given time the idlemgr will call epoll(), which reduces the lcore load to
effectively zero and only waking up when packets arrive or a timeout occurs.

In testing of performance it appears to be very little impact when interrupt
mode is enabled compared to when it is not enabled. Added some counters to help
determine how the new mode is operating.

The idle_timeout value in the jsonc file for given thread is how this feature
is controlled. If not defined or set to zero interrupt mode is disabled. When
set to a non zero value will enable interrupt mode. The intr_timeout value
is only used if idle_timeout is non-zero and will be used in the poll() call
as the timeout value. Each of these values are in milliseconds.

Use Cases
---------

The use case for idlemgr is to reduce the CPU load to zero or close to zero when
the application receive traffic is not present. By allowing the application to
stop polling for a given period of time we can reduce the CPU power and save the
customer money.

Anatomy of Idlemgr
------------------

The cndp/examples/cndpfwd application has two new items in the thread section of the json-c file. The two new items are idle_timeout and intr_timeout.
The idle_timeout is used to detect in milliseconds when the receive path of a lport is idle. The intr_timeout in milliseconds is used in epoll() to timeout a waiting thread.

Example from the fwd.jsonc thread section.

.. code-block:: console

   // List of threads to start and information for that thread. Application can start
   // its own threads for any reason and are not required to be configured by this file.
   //
   //   Key/Val   - (R) A unique thread name.
   //                   The format is <type-string>[:<identifier>] the ':' and identifier
   //                   are optional if all thread names are unique
   //      group  - (O) The lcore-group this thread belongs to. The
   //      lports - (O) The list of lports assigned to this thread and cannot be shared with other threads.
   //      idle_timeout  - (O) if non-zero use value in milliseconds to detect idle state
   //      intr_timeout  - (O) number of milliseconds to wait on interrupt
   //      description | desc - (O) The description
   "threads": {
     "main": {
       "group": "initial",
       "description": "Main Thread"
     },
     "fwd:0": {
       "group": "group0",
       "lports": ["enp134s0f0:0", "enp134s0f1:0"],
       "idle_timeout": 10,
       "intr_timeout": 2000,
       "description": "Forward thread 0"
     },
     "fwd:1": {
        "group": "group1",
        "lports": ["enp175s0f0:0", "enp175s0f1:0"],
        "idle_timeout": 10,
        "intr_timeout": 2000,
        "description": "Forward thread 1"
     }
   }

How to use the idlemgr
----------------------

How to use idlemgr for any type of file descriptor, but normally we use it for AF_XDP sockets.
The code is taken from the cndpfwd example and you can look at that file for more details.

A thread needs to call idlemgr_create()

.. code-block:: c

   idlemgr_t *imgr = NULL;
   imgr = idlemgr_create(thd->name, thd->lport_cnt, thd->idle_timeout, thd->intr_timeout);
   if (!imgr)
      CNE_ERR_GOTO(leave, "failed to create idle managed\n");

The arguments is a name can be any unique string, the number of file descriptors to
be used, the idle_timeout in ms, intr_timeout in ms. This create a epoll() group and
then allows the thread to add file descriptors to the list of epoll() managed FDs.

Calling idlemgr_add(imgr, fd, 0) to add file descriptors to the epoll() group for this thread.

.. code-block:: c

   if (xskdev_get_fd(pd->xsk, &fd, NULL) < 0)
      CNE_ERR_GOTO(leave, "failed to get file descriptors for %s\n", lport->name);

The xskdev_get_fd() needs to be passed the xskdev_info_t pointer returned from the
xskdev_create() function call. Then we add the fd to idlemgr.

.. code-block:: c

   if (idlemgr_add(imgr, fd, 0) < 0)
      return -1;


After adding all of the AF_XDP lports which are managed by this thread we can proceed
to polling. In the polling loop for a thread we need to call idlemgr_process() to
inform idlemgr when has not returned any packets from the receive call.

.. code-block:: c

   if (thd->idle_timeout) {
      if (idlemgr_process(imgr, n_pkts) < 0)
         CNE_ERR_GOTO(leave, "idlemgr_process failed\n");
   }

When idlemgr detects all of the lports (or file descriptors in the group) have become
idle using the idle_timeout value it will then call epoll() using the intr_timeout value.
The function will return from epoll() when it times out or when the file descriptor
has data to receive.
