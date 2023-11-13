#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) Red Hat Inc.

sysctl -p /etc/sysctl.d/90-routing-sysctl.conf
# shellcheck source=/dev/null
source logging.sh
# shellcheck source=/dev/null
source /usr/lib/frr/frrcommon.sh
daemon_list
all_start
all_status
# shellcheck disable=SC2046
/usr/lib/frr/watchfrr -d $(daemon_list)
