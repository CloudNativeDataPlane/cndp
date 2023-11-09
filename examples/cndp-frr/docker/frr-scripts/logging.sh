#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) Red Hat Inc.

log_success_msg() {
                 echo "$@"
}
log_warning_msg() {
                 echo "$@" >&2
}
log_failure_msg() {
                 echo "$@" >&2
}
