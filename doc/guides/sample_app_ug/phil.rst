..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2019-2022 Intel Corporation.

Phil Sample Application
=======================

The Phil sample application demonstrates multi-tasking by using the CNDP cthread API and provides
two solutions to Dijkstra's famous dining philosopher's problem, 1) a ticket-based one and 2) a
claim-based one. The ``cthread`` library provides a cooperative multi-tasking environment that
runs in userspace on a single pthread.

Running the Application
-----------------------

After :ref:`building CNDP <building-cndp>`, run the example:

.. code-block:: console

    $ ./builddir/examples/phil/phil -c examples/phil/phil.jsonc
