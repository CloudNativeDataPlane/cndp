#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) Red Hat Inc.

docker kill client1 client2 cndp-frr1 cndp-frr2
docker rm client1 client2 cndp-frr1 cndp-frr2
docker network rm net1 net2 net3
