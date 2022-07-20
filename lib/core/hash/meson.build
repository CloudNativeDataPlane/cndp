# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2017-2022 Intel Corporation

headers = files(
	'cne_fbk_hash.h',
	'cne_hash_crc.h',
	'cne_hash.h',
	'cne_jhash.h',
	'cne_thash.h')

sources = files('cne_cuckoo_hash.c', 'cne_fbk_hash.c')

deps += [ring, cne]

libhash = library(libname, sources, install: true, dependencies: deps)
hash = declare_dependency(link_with: libhash, include_directories: include_directories('.'))

cndp_libs += hash
