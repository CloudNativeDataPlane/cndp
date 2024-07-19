
# CNDP - Cloud Native Data Plane

![GitHub Workflow Status (event)](https://img.shields.io/github/actions/workflow/status/CloudNativeDataPlane/cndp/smoke.yml)

[![License](https://img.shields.io/badge/license-BSD3-blue.svg?style=flat)](https://opensource.org/licenses/BSD-3-Clause)

## Overview

Cloud Native Data Plane (CNDP) is a collection of userspace libraries for
accelerating packet processing for cloud applications. It aims to provide better
performance than that of standard network socket interfaces by taking advantage
of platform technologies such as Intel(R) AVX-512, Intel(R) DSA, CLDEMOTE, etc.
The I/O layer is primarily built on AF_XDP, an interface that delivers packets
straight to userspace, bypassing the kernel networking stack. CNDP provides ways
to expose metrics and telemetry with examples to deploy network services on
Kubernetes.

## CNDP Consumers

- **Cloud Network Function (CNF) and Cloud Application developers**: Those who
  create applications based on CNDP. CNDP hides the low-level I/O, allowing the
  developer to focus on their application.

- **CNF and Cloud Application consumers**: Those who consume the applications
  developed by the CNF developer. CNDP showcases deployment models for their
  applications using Kubernetes.

## CNDP Characteristics

CNDP follows a set of principles:

- **Functionality**: Provide a framework for cloud native developers that offers
  full control of their application.

- **Usability**: Simplify cloud native application development to enable the
  developer to create applications by providing APIs that abstract the
  complexities of the underlying system while still taking advantage of
  acceleration features when available.

- **Interoperability**: The CNDP framework is built primarily on top of AF_XDP.
  Other interfaces, such as memif, are also supported, however building on
  AF_XDP ensures it is possible to move an application across environments
  wherever AF_XDP is supported.

- **Portability/stability**: CNDP provides ABI stability and a common API to
  access network interfaces.

- **Performance**: Take advantage of platform technologies to accelerate packet
  processing or fall-back to software when acceleration is unavailable.

- **Observability**: Provide observability into the performance and operation of
  the application.

- **Security**: Security for deployment in a cloud environment is critical.

## CNDP background

CNDP was created to enable cloud native developers to use AF_XDP and other
interfaces in a simple way while providing better performance as compared to
standard Linux networking interfaces.

CNDP does not replace DPDK (Data Plane Development Kit), which provides the
highest performance for packet processing. DPDK implements user space drivers,
bypassing the kernel drivers. This approach of rewriting drivers is one reason
DPDK achieves the highest performance for packet processing. DPDK also
implements a framework to initialize and setup platform resources i.e. scanning
PCI bus for devices, allocating memory via hugepages, setting up
Primary/Secondary process support, etc.

In contrast to DPDK, CNDP does not have custom drivers. Instead it expects the
kernel drivers to implement AF_XDP, preferably in zero-copy mode. Since there
are no PCIe drivers, there's no PCI bus scanning, and does not require
physically contiguous and pinned memory. This simplifies deployment for cloud
native applications while gaining the performance benefits provided by AF_XDP.

## Development

In order to make contributions to CNDP, you need to have the following installed:

- [Pre-commit](https://pre-commit.com/#install)

You can install pre-commit by running the following command:

```bash
pip install pre-commit
```

After installing pre-commit, you need to install the pre-commit hooks by
running the following command:

```bash
pre-commit install
```

To run pre-commit manually

```bash
pre-commit run --all-files
```

## CNDP notable directories

The following shows a subset of the directory structure.

```bash
.
├── ansible          # Ansible playbook to install in a system(s)
├── containerization # Container configuration and setup scripts for Docker/K8s
├── doc              # Documentation APIs, guides, getting started, ...
├── examples         # Example applications to understand how to use CNDP features
├── lang             # Language bindings and examples
│   ├── go           # Go Language bindings to CNDP and tools (WIP)
│   └── rs           # Rust Language bindings for CNDP/Wireguard (WIP)
├── lib              # Set of libraries for building CNDP applications
│   ├── cnet         # Userspace network stack
│   ├── common       # Libraries used by core and applications libraries
│   ├── core         # Core libraries for CNDP
│   ├── include      # Common headers for CNDP and applications
│   └── usr          # User set of libraries that are optional for developer
├── test             # Unit test framework
│   ├── common       # Common test code
│   ├── fuzz         # Fuzzing (WIP)
│   └── testcne      # Functional unit testing application
├── tools            # Tools for building CNDP
│   └── vscode       # Configuration files for vscode
└── usrtools         # Tools for users
   ├── cnectl        # Remote CLI for CNDP applications
   └── txgen         # Traffic Generator using AF_XDP and CNDP
```
