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

# Use V=1 on the make line to enable verbose output
ifeq ($V,1)
	verbose=-v
else
	verbose=
endif

all: FORCE
	${Build} build

build: FORCE
	${Build} ${verbose} build

rebuild: FORCE
	${Build} ${verbose} clean build

rebuild-install: FORCE
	${Build} ${verbose} clean build install

coverity: FORCE
	${Build} ${verbose} clean coverity

debug: FORCE
	${Build} ${verbose} debug

debugopt: FORCE
	${Build} ${verbose} debugopt

clean: FORCE
	${Build} ${verbose} clean

install: FORCE
	${Build} ${verbose} install

uninstall: FORCE
	${Build} ${verbose} uninstall

docs: FORCE
	${Build} ${verbose} docs

help: FORCE
	${Build} ${verbose} help

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

docker-image: FORCE
	docker build -t cndp --build-arg http_proxy=${http_proxy} \
  --build-arg https_proxy=${http_proxy} -f containerization/docker/ubuntu/Dockerfile .

docker-fed-image: FORCE
	docker build -t cndp-fedora --build-arg http_proxy=${http_proxy} \
  --build-arg https_proxy=${http_proxy} -f containerization/docker/fedora/Dockerfile .

rust-app: FORCE
	${Build} rust-app

rust-app-clean: FORCE
	${Build} rust-app-clean

docker-run: FORCE
	docker run --privileged --network=host -it cndp bash

docker-fed-run: FORCE
	docker run --privileged --network=host -it cndp-fedora bash

FORCE:
