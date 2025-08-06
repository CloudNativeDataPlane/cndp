..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2019-2025 Intel Corporation.

Hello World Sample Application
==============================

The Hello World sample application is an example of a simple CNDP application. The application
prints some system information and 'hello world' from each thread.

Running the Application
-----------------------

To run the example:

.. code-block:: console

    $ ./builddir/examples/helloworld/helloworld

    Max threads: 512, Max lcores: 72, NUMA nodes: 2, Num Threads: 1

    hello world! thread id    1

    Waiting for all threads to stop!

    hello world! thread id    1 Done

    All threads have stopped!

    Good Bye!
