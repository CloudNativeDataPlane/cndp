#!/bin/bash

sysctl -p /etc/sysctl.d/90-routing-sysctl.conf
source logging.sh
source /usr/lib/frr/frrcommon.sh
daemon_list
all_start
all_status
/usr/lib/frr/watchfrr -d $(daemon_list)