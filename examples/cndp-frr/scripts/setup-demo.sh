#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) Red Hat Inc.
#########################################
############ Create networks ############
#########################################
docker network create net1 --subnet=172.19.0.0/16
docker network create net2 --subnet=172.20.0.0/16
docker network create net3 --subnet=172.21.0.0/16

#########################################
############ Run containers #############
#########################################
docker run -u root -dit --name client1 --privileged --net net1 cndp-frr
docker run -u root -dit --name client2 --privileged --net net3 cndp-frr
docker run -dit --name cndp-frr1 --privileged --net net1 cndp-frr
docker run -dit --name cndp-frr2 --privileged --net net2 cndp-frr

###############################################################
############ Connect containers to second Network #############
###############################################################
docker network connect net2 cndp-frr1
docker network connect net3 cndp-frr2

#########################################
############  Setup routes  #############
#########################################
docker exec client1 route add default gw 172.19.0.3
docker exec client1 route del default gw 172.19.0.1
docker exec client2 route add default gw 172.21.0.3
docker exec client2 route del default gw 172.21.0.1

#########################################
############ Setup FRR configs ##########
#########################################
docker exec cndp-frr1 cp /frr1.cfg /etc/frr/frr.conf
docker exec cndp-frr2 cp /frr2.cfg /etc/frr/frr.conf

###############################################################
############  Create BPFFS on cndp-frr1 #######################
###############################################################
docker exec cndp-frr1 mount bpffs /sys/fs/bpf/ -t bpf
docker exec cndp-frr1 mkdir -p /sys/fs/bpf/eth0/
docker exec cndp-frr1 mkdir -p /sys/fs/bpf/eth1/

###############################################################
############ Load BPF UDP filter prog on cndp-frr1 ############
###############################################################
docker exec cndp-frr1 xdp-loader load eth0 /cndp-frr/my-filter-udp-to-xdp/my_xdp_prog_kern.o -p /sys/fs/bpf/eth0/
docker exec cndp-frr1 xdp-loader load eth1 /cndp-frr/my-filter-udp-to-xdp/my_xdp_prog_kern.o -p /sys/fs/bpf/eth1/

###############################################################
############  Create BPFFS on cndp-frr2 #######################
###############################################################
docker exec cndp-frr2 mount bpffs /sys/fs/bpf/ -t bpf
docker exec cndp-frr2 mkdir -p /sys/fs/bpf/eth0/
docker exec cndp-frr2 mkdir -p /sys/fs/bpf/eth1/

###############################################################
############ Load BPF UDP filter prog on cndp-frr2 ############
###############################################################
docker exec cndp-frr2 xdp-loader load eth0 /cndp-frr/my-filter-udp-to-xdp/my_xdp_prog_kern.o -p /sys/fs/bpf/eth0/
docker exec cndp-frr2 xdp-loader load eth1 /cndp-frr/my-filter-udp-to-xdp/my_xdp_prog_kern.o -p /sys/fs/bpf/eth1/

##########################################################
#### Fix for FRR not starting up in a VM #################
### fork(): Cannot allocate memory Failed to start zebra!#
##########################################################
echo 1 > /proc/sys/vm/overcommit_memory
