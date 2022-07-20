# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2018-2022 Intel Corporation

sources = files('cthread.c', 'cthread_tls.c', 'cthread_sema.c', 'cthread_sched.c',
		'cthread_mutex.c', 'cthread_cond.c', 'cthread_barrier.c',
		'ctx.c')
headers = files('cthread.h', 'cthread_api.h')

deps += [ring, timer, cne]

libcthread = library(libname, sources, install: true, dependencies: deps)
cthread = declare_dependency(link_with: libcthread, include_directories: include_directories('.'))

cndp_libs += cthread
