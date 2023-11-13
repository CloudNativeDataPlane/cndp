#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) Red Hat Inc.

if [ "$(docker ps -a -q -f name=client1)" ]; then
    docker kill client1; docker rm client1
fi

if [ "$(docker ps -a -q -f name=client2)" ]; then
    docker kill client2; docker rm client2
fi

if [ "$(docker ps -a -q -f name=cndp-frr1)" ]; then
    docker kill cndp-frr1; docker rm cndp-frr1
fi

if [ "$(docker ps -a -q -f name=cndp-frr2)" ]; then
    docker kill cndp-frr2; docker rm cndp-frr2
fi

if [ "$(docker network ls -q -f name=net1)" ]; then
    docker network rm net1
fi

if [ "$(docker network ls -q -f name=net2)" ]; then
    docker network rm net2
fi

if [ "$(docker network ls -q -f name=net3)" ]; then
    docker network rm net3
fi
