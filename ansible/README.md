# CNDP Ansible Playbook

## Overview

CNDP provides an Ansible playbook to install all CNDP dependencies and setup the CNDP env.

Though CNDP can run on many distributions and kernels, the preferred environment is for an Ubuntu
20.04 installation. This is chosen as its the most recent LTS version, and the kernel can be
updated from the package manager to one which natively supports many AF_XDP features.

## Prerequisites

### apt proxy

If required, create a proxy.conf and configure the apt proxy settings.

```bash
cat << EOF | sudo tee -a /etc/apt/apt.conf.d/proxy.conf
Acquire::http::Proxy "http://user:password@proxy.server:port/";
Acquire::https::Proxy "https://user:password@proxy.server:port/";
EOF
```

### dependencies

#### Ubuntu
apt-get should now work to install the packages needed to use ansible.

```bash
sudo apt update
sudo apt-get install -y ansible
```
#### Fedora
Install ansible using dnf

```bash
sudo dnf install -y ansible
```

> Note: if ansible isn't available in the package tree, it can be installed by
following these
[instructions](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html#installing-ansible-on-ubuntu).

### SSH Key Setup

Ansible uses ssh to load and run it's modules on the target host. As such, it's important to setup a
SSH key and copy it to the target node (note: the target node maybe the localhost).

As root on both nodes run:

```bash
ssh-keygen
ssh-copy-id <target>
```
where <target> is an IP address or localhost.


Three playbooks are provided:
1. multi-host.yml: Requires a control node and a managed node.
2. localhost-kernel-install.yml: Installs all the required packages and updates kernel to 5.13 (for ubuntu 20.04)
   with XDP enabled (on the localhost). A user is expected to reboot the system after this script
   runs.
3. localhost-post-kernel-install.yml: Installs any additional libraries needed for
   CNDP after the Kernel is updated and rebooted.

Before running the playbooks it's important to modify the following files:
1. hosts.ini: to add the hosts that you wish the multi-node playbook to setup.
2. group_vars/all: to edit proxy and distribution variables.

### CNDP Ansible tree
Below is the full directory tree of Ansible playbooks and roles.

```bash
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
```

## Running the Ansible playbook

> Note: it's important to edit group_vars/all and hosts.ini before running any playbooks.

```bash
sudo ansible-playbook -i hosts.ini <playbook_name>
```

> Note: you will need to manually reboot the host after using the localhost-kernel-install.yml
playbook

### Building CNDP

After running Ansible to install all the dependencies, please set `PKG_CONFIG_PATH`, then CNDP can be built by typing `make` in the
top level dir:

```bash
export PKG_CONFIG_PATH=/usr/lib/pkgconfig
make rebuild-install
```
