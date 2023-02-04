# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2023 Intel Corporation

subdir('tun')
subdir('net')

# These need to be here as some headers are being installed twice. In this case, the
# last pmd directory headers are being installed twice (memif). Tried to track down the
# duplicated headers being install, but is seems to be a race condition in ninja (IMO)
# calling the different directories with multiple threads.
sources = []
headers = []
