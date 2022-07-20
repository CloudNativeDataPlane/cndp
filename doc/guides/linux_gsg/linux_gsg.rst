..  SPDX-License-Identifier: BSD-3-Clause
    Copyright (c) 2019-2022 Intel Corporation.

Introduction
============

This document contains instructions to install and configure the Cloud Native Data Plane (CNDP).

Documentation Roadmap
---------------------

The following is a list of documents in the suggested reading order:

 * **Getting Started Guide (this document)**: First step to get started with CNDP.

 * **Release Notes**: Release-specific information including new features, limitations, and fixed
   and known issues.

 * **Programmer's Guide**: The software architecture and contents of CNDP.

 * **Poll Mode Drivers (PMD) Guide**: The drivers implementing the pktdev API.

 * **API Reference**: Detailed information about CNDP functions, data structures, and other
   programming constructs.

 * **Sample Applications User Guide**: Describe the collection of sample applications. Each chapter
   describes a sample application that showcases specific functionality with instructions on how to
   use the sample application.

 * **Test-cne**: Describe the unit test framework.

.. _building-cndp:

System Requirements and Building CNDP
=====================================

This chapter describes the packages required to compile CNDP. It assumes you are building on an
Ubuntu 21.04 host.

To bypass manual installation, use the ansible scripts provided by CNDP in the section:
`Installation of CNDP requirements using Ansible`_.

BIOS Settings
-------------

No special BIOS settings are needed to use CNDP.

Install CNDP Manually
---------------------

System Software
~~~~~~~~~~~~~~~

**Required:**

* Kernel version >= 5.0.0

   Kernel must be built with XDP support. The default kernel for Ubuntu 20.04 and later have AF_XDP
   support.

.. code-block:: console

   CONFIG_BPF=y
   CONFIG_BPF_SYSCALL=y
   CONFIG_XDP_SOCKETS=y

* libbpf from kernel source tree (kernel 5.0.0 or later), or Ubuntu package, or github.com.

* OS is Ubuntu 20.04 or later. Other Linux versions work, but this documentation assumes Ubuntu.

* CNDP requires the following packages, some of which have recursive dependencies:

  * pkg-config
  * libbsd-dev
  * build-essential
  * libelf-dev
  * libpcap-dev
  * meson
  * doxygen
  * python3-sphinx
  * libnl-3-dev
  * libnl-cli-3-dev

.. _linux_gsg_hugepages:

Hugepages
~~~~~~~~~

Hugepage support is optional, but preferred. Performance is increased when using hugepages since
fewer pages are needed, and therefore less Translation Lookaside Buffer (TLB) entries are used. This
reduces the time it takes to translate a virtual page address to a physical page address. Without
hugepages, high TLB miss rates might occur with the standard 4KB page size, potentially reducing
performance.

Reserving Hugepages
^^^^^^^^^^^^^^^^^^^

The allocation of hugepages should be done at boot time or as soon as possible after system boot to
prevent physical memory fragmentation. To reserve hugepages at boot time, a parameter is passed to
the Linux kernel on the kernel command line.

For 2MB pages, just pass the hugepages option to the kernel. For example, to reserve 1024 pages of
2MB size, use::

   hugepages=1024

For 1GB pages, the size must be specified explicitly and can also be optionally set as the default
hugepage size for the system. For example, to reserve 4GB of hugepage memory in the form of
four 1GB pages, the following options should be passed to the kernel::

   default_hugepagesz=1G hugepagesz=1G hugepages=4

.. note::

   The hugepage sizes that a CPU supports can be determined from the CPU flags. If pse exists, 2MB
   hugepages are supported; if pdpe1gb exists, 1GB hugepages are supported.

.. note::

   For 64-bit applications, it is recommended to use 1GB hugepages if the platform supports them.

In the case of a dual-socket NUMA system, the number of hugepages reserved at boot time is generally
divided equally between the two sockets (on the assumption that sufficient memory is present on both
sockets).

See the Documentation/admin-guide/kernel-parameters.txt file in your Linux source tree for further
details of these and other kernel options.

**Alternative:**

For 2MB pages, there is also the option of allocating hugepages after the system has booted. This is
done by writing the number of hugepages required to a nr_hugepages file in the ``/sys/devices/``
directory. For a single-node system, the command to use is as follows (assuming that 1024 pages are
required)::

   echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages

On a NUMA machine with two nodes, pages should be allocated explicitly on separate nodes::

   echo 1024 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
   echo 1024 > /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages

.. note::

   For 1GB pages, it is not possible to reserve the hugepage memory after the system has booted.

Prerequisites
~~~~~~~~~~~~~

If behind a proxy server you may need to setup a number of configurations to allow access via the server.
Some commands i.e. apt-get, git, ssh, curl, wget and others will need configuration to work correctly.
Please refer to apt-get, git and other documentations to enable access through a proxy server.

Optionally update apt-get.

.. code-block:: console

   sudo apt-get update

Apt-get is used to install the required packages to build CNDP and its dependencies.

Build libbpf
~~~~~~~~~~~~

The `libbpf <https://github.com/libbpf/libbpf>`_ is a dependency of CNDP. Starting with Ubuntu 20.10
the libbpf libraries can be installed using apt-get. For earlier Ubuntu versions, or for users who
want the latest code, it can be installed from source.

**Install using apt-get**

.. code-block:: console

   sudo apt-get install -y libbpf-dev

**Or install from source**

Install packages to build libbpf

.. code-block:: console

   sudo apt-get install -y build-essential pkg-config libelf-dev

Clone, build, and install libbpf
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

   git clone https://github.com/libbpf/libbpf.git
   cd libbpf
   git checkout v0.5.0   # or you can use v0.6.1 if needing a newer version
   make -C src
   sudo make -C src install
   export PKG_CONFIG_PATH=/usr/lib64/pkgconfig

Edit the file /etc/ld.so.conf.d/x86_64-linux-gnu.conf and add the line /usr/lib64 to the
bottom of the file.

.. code-block:: console

   sudo vim /etc/ld.so.conf.d/x86_64-linux-gnu.conf   # add /usr/lib64 to file
   sudo ldconfig     # force ldconfig to detect changes

Build CNDP
~~~~~~~~~~

Install packages to build CNDP

.. code-block:: console

   sudo apt-get install -y build-essential libbsd-dev libelf-dev libjson-c-dev\
    libnuma-dev libpcap-dev meson pkg-config libnl-3-dev libnl-cli-3-dev

Optionally install packages to build documentation

.. code-block:: console

   sudo apt-get install -y doxygen python3-sphinx

Clone and build CNDP
^^^^^^^^^^^^^^^^^^^^

.. code-block:: console

   git clone https://github.com/CloudNativeDataPlane/cndp.git
   cd cndp
   make

Other targets exist, most are wrappers around tools/cne-build.sh.

.. code-block:: console

   make help

or rebuild will clean and build CNDP with -O3

.. code-block:: console

   make rebuild

or to build a debug image with -O0

.. code-block:: console

   make clean debug

or to build the docs

.. code-block:: console

   make docs

or to build a statically linked executable. Use the commandline make option 'static_build=1' to build
libraries and executables as static binaries.

When switching between static and shared builds the install directory could contain extra libraries
in *usr/local/lib/x86_64-linux-gnu* .so libraries if building static or .a libraries if building shared.

Need to do a *'make uninstall clean build'* or *'make static_build=1 uninstall clean build'*
commands. If you have both types of libraries the quickest way is to do 'rm -fr usr/local/\*' **No leading '/'**.

.. note:: **(Do NOT use rm -fr /usr/local/\*)**, note the leading **'/'** should **NOT** be present or you can remove
  your /usr/local directory if running as root. You should not be building CNDP
  as root as too many problems like this one can happen.

.. code-block:: console

   make static_build=1 uninstall clean build

or use 'rebuild' instead of 'clean build' which the same thing.

.. code-block:: console

   make static_build=1 uninstall rebuild


Run CNDP examples
^^^^^^^^^^^^^^^^^

helloworld
""""""""""

The most basic example is ``helloworld``.

.. code-block:: console

   ./builddir/examples/helloworld/helloworld
   Max threads: 512, Max lcores: 32, NUMA nodes: 1, Num Threads: 1
   hello world! from thread index 0 for index 0
   Ctrl-C to exit

cndpfwd
"""""""

An example that uses networking is ``cndpfwd``. It requires the underlying network interface
uses, e.g. AF_XDP sockets. Make sure the kernel on which you intend to run the application
supports AF_XDP sockets, i.e. CONFIG_XDP_SOCKETS=y.

.. code-block:: console

   grep XDP_SOCKETS= /boot/config-`uname -r`

Configure an ethtool filter to steer packets to a specific queue.

.. code-block:: console

   sudo ethtool -N <devname> flow-type udp4 dst-port <dport> action <qid>
   sudo ip link set dev <devname> up

Instruct ``cndpfwd`` to receive, count, and drop all packets on the previously configured
queue. To configure ``cndpfwd``, edit the examples/cndpfwd/fwd.jsonc configuration file. Make
sure the "lports" section has the same netdev name and queue id for which the ethtool filter
is configured. Make sure the "threads" section has the correct "lports" configured. Then
launch the application, specifying the updated configuration file.

.. code-block:: console

   sudo ./builddir/examples/cndpfwd/cndpfwd -c examples/cndpfwd/fwd.jsonc drop


Installation of CNDP requirements using Ansible
-----------------------------------------------

CNDP provides an Ansible playbook to install all CNDP dependencies and setup the CNDP env.

Though CNDP can run on many distributions and kernels, the preferred environment is for an Ubuntu
20.04 installation. This is chosen as its the most recent LTS version, and the kernel can be
updated from the package manager to one which natively supports many AF_XDP features.

Prerequisites
~~~~~~~~~~~~~

dependencies
^^^^^^^^^^^^

apt-get should now work to install the packages needed to use ansible.

.. code-block:: console

   sudo apt-get update
   sudo apt-get install -y ansible

.. note::

   If ansible isn't available in the package tree, it can be installed by
   following these `instructions <https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html#installing-ansible-on-ubuntu>`_.

SSH Key Setup
^^^^^^^^^^^^^

Ansible uses ssh to load and run it's modules on the target host. As such, it's important to setup a
SSH key and copy it to the target node (note: the target node maybe the localhost).

As root on both nodes run:

.. code-block:: console

   ssh-keygen
   ssh-copy-id <target>

where <target> is an IP address or localhost.

CNDP Ansible tree
~~~~~~~~~~~~~~~~~

Below is the full directory tree of Ansible playbooks and roles.

.. code-block:: console

   .
   ├── group_vars
   │   └── all    // contains global variable for ansible
   ├── hosts.ini  // contains the host ip addresses that you which to configure
   ├── localhost-kernel-install.yml       // playbook
   ├── localhost-post-kernel-install.yml  // playbook
   ├── multi-host.yml                     // playbook
   └── roles
       ├── check_hugepages
       │   └── tasks
       │       └── main.yml
       ├── check_os
       │   └── tasks
       │       └── main.yml
       ├── check_updated_kernel
       │   └── tasks
       │       └── main.yml
       ├── common
       │   └── tasks
       │       └── main.yml
       ├── install_kernel
       │   └── tasks
       │       └── main.yml
       ├── install_libbpf
       │   └── tasks
       │       └── main.yml
       └── setup_hugepages
           └── tasks
               └── main.yml

Three playbooks are provided:

#. multi-host.yml: Requires a control node and a managed node.

#. localhost-kernel-install.yml: Installs all the required packages and updates kernel to 5.13
   with XDP enabled (on the localhost). A user is expected to reboot the system after this script
   runs.

#. localhost-post-kernel-install.yml: Installs any additional libraries needed for
   CNDP after the Kernel is updated and rebooted.

Before running the playbooks it's important to modify the following files:

#. hosts.ini: to add the hosts that you wish the multi-node playbook to setup.

#. group_vars/all: to edit proxy variables.

Running the Ansible playbook
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. note::

   It's important to edit group_vars/all and hosts.ini before running any playbooks.

.. code-block:: console

   sudo ansible-playbook -i hosts.ini <playbook_name>

.. note::

   You will need to manually reboot the host after using the localhost-kernel-install.yml playbook

Building CNDP
~~~~~~~~~~~~~

After running Ansible to install all the dependencies, CNDP can be built by typing `make` in the
top level dir:

.. code-block:: console

   make
