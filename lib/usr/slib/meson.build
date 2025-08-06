# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2025 Intel Corporation

dirs = [
    'csock', # support for cndp socket access via new stdio support, shared between CNDP and system
]

if cne_conf.get('HAS_UINTR_SUPPORT')
    dirs += ['ibroker']
endif

foreach d:dirs
    libname = 'cne_' + d
    enabled_libs += libname
	subdir(d)

	install_headers(headers, subdir: meson.project_name().to_lower())
endforeach
