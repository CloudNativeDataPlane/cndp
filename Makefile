# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2025 Intel Corporation

#
# Head Makefile for compiling CNDP, but just a wrapper around
# meson and ninja using the tools/cnd-build.sh script.
#
# Use 'make' or 'make build' to build CNDP. If the build directory does
# not exist it will be created with these two build types.
#

mkfile_path=$(abspath $(lastword $(MAKEFILE_LIST)))
source_dir=$(shell dirname "$(mkfile_path)")
Build="${source_dir}/tools/cne-build.sh"
CE?=docker #Container Engine
ContainerEngine=$(shell echo $(CE) | tr A-Z a-z)
Builder := $(shell which docker 2>/dev/null || which podman)
OCI-Builder ?= $(shell basename ${Builder})

# Use V=1 on the make line to enable verbose output
ifeq ($V,1)
	verbose=-v
else
	verbose=
endif

ifeq (${tcp},1)
    tcp_build=tcp
else
    tcp_build=
endif

ifeq (${ipv6},1)
    ipv6_build=ipv6
else
    ipv6_build=
endif

ifeq (${static_build},1)
    build_static=static
else
    build_static=
endif

all: FORCE
	${Build} ${verbose} ${tcp_build} ${ipv6_build} ${build_static} build

help: FORCE
	${Build} help
	@echo ""
	@echo "Makefile options:"
	@echo " Adding 'static_build=1' to the make line enables building static files"
	@echo "    eg: 'make static_build=1 rebuild install' for static executables"
	@echo " Adding 'tcp=1' to enable TCP building"
	@echo "    eg: 'make tcp=1 rebuild-install' to enable TCP support"
	@echo " Adding 'ipv6=1' to enable IPv6 building"
	@echo "    eg: 'make ipv6=1 rebuild-install' to enable IPv6 support"
	@echo " Adding 'V=1' to enable verbose build messages"

build: FORCE
	${Build} ${verbose} ${tcp_build} ${ipv6_build} ${build_static} build

rebuild: FORCE
	${Build} ${verbose} ${tcp_build} ${ipv6_build} clean ${build_static} build

rebuild-install: FORCE
	${Build} ${verbose} ${tcp_build} ${ipv6_build} clean ${build_static} build install

coverity: FORCE
	${Build} ${verbose} clean coverity

debug: FORCE
	${Build} ${verbose} ${tcp_build} ${ipv6_build} ${build_static} debug

debugopt: FORCE
	${Build} ${verbose} ${tcp_build} ${ipv6_build} ${build_static} debugopt

clean: FORCE
	${Build} ${verbose} clean

install: FORCE
	${Build} ${verbose} install

uninstall: FORCE
	${Build} ${verbose} uninstall

docs: FORCE
	${Build} ${verbose} docs

py-reqs: FORCE
# regenerate requirements.txt for all Python files
	tools/gen_requirements.sh

snyk: FORCE
# scan python code
	snyk monitor --command=python3 --file=tools/requirements.txt
# scan go code
	@for d in $(shell find -name "go.mod") ; do \
		snyk monitor --file=$${d} ; \
	done

oci-image: FORCE
ifeq ($(OCI-Builder), docker)
	@echo "docker selected"
else ifeq ($(OCI-Builder), buildah)
	@echo "buildah selected"
else ifeq ($(OCI-Builder), podman)
	@echo "podman selected"
else
	@echo "UNKNOWN OCI IMAGE builder $(OCI-Builder)"
	exit 1
endif
	${OCI-Builder} build -t cndp --build-arg http_proxy=${http_proxy} \
  --build-arg https_proxy=${http_proxy} -f containerization/docker/ubuntu/Dockerfile .

oci-fed-image: FORCE
ifeq ($(OCI-Builder), docker)
	@echo "docker selected"
else ifeq ($(OCI-Builder), buildah)
	@echo "buildah selected"
else
	@echo "UNKNOWN OCI IMAGE builder $(OCI-Builder)"
	exit 1
endif
	$(OCI-Builder) build -t cndp-fedora --build-arg http_proxy=${http_proxy} \
  --build-arg https_proxy=${http_proxy} -f containerization/docker/fedora/Dockerfile .

cndp-frr-image: FORCE
ifeq ($(OCI-Builder), docker)
	@echo "docker selected"
else ifeq ($(OCI-Builder), buildah)
	@echo "buildah selected"
else
	@echo "UNKNOWN OCI IMAGE builder $(OCI-Builder)"
	exit 1
endif
	$(OCI-Builder) build -t cndp-frr --build-arg http_proxy=${http_proxy} \
  --build-arg https_proxy=${http_proxy} -f examples/cndp-frr/docker/Dockerfile .

rust-app: FORCE
	${Build} rust-app

rust-app-clean: FORCE
	${Build} rust-app-clean

ce-run: FORCE
ifeq ($(ContainerEngine), docker)
	@echo "docker selected"
else ifeq ($(ContainerEngine), podman)
	@echo "podman selected"
else
	@echo "UNKNOWN Container Engine $(ContainerEngine)"
	exit 1
endif
	$(ContainerEngine) run --privileged --network=host -it cndp bash

ce-fed-run: FORCE
ifeq ($(ContainerEngine), docker)
	@echo "docker selected"
else ifeq ($(ContainerEngine), podman)
	@echo "podman selected"
else
	@echo "UNKNOWN Container Engine $(ContainerEngine)"
	exit 1
endif
	$(ContainerEngine) run --privileged --network=host -it cndp-fedora bash

cndp-frr-run: FORCE
	@echo "Starting up cndp-frr example"
	./examples/cndp-frr/scripts/setup-demo.sh

cndp-frr-clean: FORCE
	@echo "Cleaning up cndp-frr example"
	./examples/cndp-frr/scripts/cleanup-demo.sh

FORCE:
