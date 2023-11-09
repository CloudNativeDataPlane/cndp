#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) Red Hat Inc.

sysctl -p /etc/sysctl.d/90-routing-sysctl.conf
source logging.sh
source /usr/lib/frr/frrcommon.sh
daemon_list
all_start
all_status
/usr/lib/frr/watchfrr -d $(daemon_list)
