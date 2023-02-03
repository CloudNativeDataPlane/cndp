# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

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
Builder?=docker #OCI Image Builder
CE?=docker #Container Engine
OCI-Builder=$(shell echo $(Builder) | tr A-Z a-z)
ContainerEngine=$(shell echo $(CE) | tr A-Z a-z)

# Use V=1 on the make line to enable verbose output
ifeq ($V,1)
	verbose=-v
else
	verbose=
endif

all: FORCE
ifeq (${static_build},1)
	${Build} ${verbose} static build
else
	${Build} ${verbose} build
endif

help: FORCE
	${Build} help
	@echo ""
	@echo "Makefile options:"
	@echo " Adding 'static_build=1' to the make line enables building static files"
	@echo "    eg: 'make static_build=1 rebuild install' for static executables"

build: FORCE
ifeq (${static_build},1)
	${Build} ${verbose} static build
else
	${Build} ${verbose} build
endif

rebuild: FORCE
ifeq (${static_build},1)
	${Build} ${verbose} clean static build
else
	${Build} ${verbose} clean build
endif

rebuild-install: FORCE
ifeq (${static_build},1)
	${Build} ${verbose} clean static build install
else
	${Build} ${verbose} clean build install
endif

coverity: FORCE
	${Build} ${verbose} clean coverity

debug: FORCE
ifeq (${static_build},1)
	${Build} ${verbose} static debug
else
	${Build} ${verbose} debug
endif

debugopt: FORCE
ifeq (${static_build},1)
	${Build} ${verbose} static debugopt
else
	${Build} ${verbose} debugopt
endif

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
else
	@echo "UNKOWN OCI IMAGE builder $(OCI-Builder)"
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
	@echo "UNKOWN OCI IMAGE builder $(OCI-Builder)"
	exit 1
endif
	$(OCI-Builder) build -t cndp-fedora --build-arg http_proxy=${http_proxy} \
  --build-arg https_proxy=${http_proxy} -f containerization/docker/fedora/Dockerfile .

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
	@echo "UNKOWN Container Engine $(ContainerEngine)"
	exit 1
endif
	$(ContainerEngine) run --privileged --network=host -it cndp bash

ce-fed-run: FORCE
ifeq ($(ContainerEngine), docker)
	@echo "docker selected"
else ifeq ($(ContainerEngine), podman)
	@echo "podman selected"
else
	@echo "UNKOWN Container Engine $(ContainerEngine)"
	exit 1
endif
	$(ContainerEngine) run --privileged --network=host -it cndp-fedora bash

FORCE:
