..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2019-2022 Intel Corporation.

.. _getting_started:

Getting Started with TXGen
===========================

This section contains instructions on how to get up and running with `CNDP
<http://cndp.org/>`_ and the ``txgen`` traffic generator application.

These instructions relate to setting up CNDP and ``txgen`` on an Ubuntu
desktop system. However, the should work on any recent Linux system with
kernel support for hugeTLB/hugepages.


System requirements
-------------------

The main system requirement is that the CNDP packet processing framework is
supported.

Setting up hugeTLB/hugepage support
-----------------------------------

To get hugeTLB/hugepage support your Linux kernel must be at least 2.6.33 and
the ``HUGETLBFS`` kernel option must be enabled.

The CNDP Linux Getting Started Guide has a section on the `Use of Hugepages in
the Linux Environment
<http://www.cndp.org/doc/guides/linux_gsg/sys_reqs.html#use-of-hugepages-in-the-linux-environment>`_.

Once you have made the required changed make sure you have HUGE TLB support in the kernel with the following commands::

   $ grep -i huge /boot/config-2.6.35-24-generic
   CONFIG_HUGETLBFS=y
   CONFIG_HUGETLB_PAGE=y

   $ grep -i huge /proc/meminfo

   HugePages_Total:      128
   HugePages_Free:       128
   HugePages_Rsvd:        0
   HugePages_Surp:        0
   Hugepagesize:       2048 kB


The values in Total and Free may be different depending on your system.

You will need to edit the ``/etc/sysctl.conf`` file to setup the hugepages
size::

   $ sudo vi /etc/sysctl.conf
   Add to the bottom of the file:
   vm.nr_hugepages=256

You can configure the ``vm.nr_hugepages=256`` as required. In some cases
making it too small will effect the performance of txgen or cause it to
terminate on startup.

You will also need to edit the ``/etc/fstab`` file to mount the hugepages at
startup::

   $ sudo vi /etc/fstab
   Add to the bottom of the file:
   huge /mnt/huge hugetlbfs defaults 0 0

   $ sudo mkdir /mnt/huge
   $ sudo chmod 777 /mnt/huge

You should also reboot your machine as the huge pages must be setup just after
boot to make sure there is enough contiguous memory for the 2MB pages.

.. Note::

   If you start an application that makes extensive use of hugepages, such as
   Eclipse or WR Workbench, before starting ``txgen`` for the first time
   after reboot, ``txgen`` may fail to load. In this case you should close
   the other application that is using hugepages.



BIOS settings
-------------

In the BIOS make sure that the HPET High Precision Event Timer is
enabled. Also make sure hyper-threading is enabled. See the CNDP documentation
on `enabling additional BIOS functionality
<http://www.cndp.org/doc/guides/linux_gsg/enable_func.html#enabling-additional-functionality>`_
for more details.


Terminal display
----------------

The ``txgen`` output display requires 132 columns and about 42 lines to
display correctly. The author uses an xterm of 132x42, but you can also have a
larger display and maybe a bit smaller. If you are displaying more then 4-6
lports then you will need a wider display.

TXGen allows you to view a set lports via the ``page`` runtime command if they
do not all fit on the screen at one time, see :ref:`commands`.

TXGen uses VT100 control codes display its output screens, which means your
terminal must support VT100.

It is also best to set your terminal background to black when working with the
default ``txgen`` color scheme.



Get the source code
-------------------

TXGen requires the CNDP source code to build.

The main ``cndp`` and ``txgen`` git repositories are hosted on `cndp.org
<http://www.cndp.org/browse/>`_.

The ``cndp`` code can be cloned as follows::

   git clone git://cndp.org/cndp
   # or:
   git clone http://cndp.org/git/cndp

The ``txgen`` code can be cloned as follows::

   git clone git://cndp.org/apps/txgen-cndp
   # or:
   git clone http://cndp.org/git/apps/txgen-cndp

Build CNDP and TXGen
---------------------

TXGen can then be built as follows::

   $ cd <InstallDir>
   $ meson build
   $ ninja -C build
