# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2022 Intel Corporation

project('CNDP CNE bindings for Rust', 'c',
  version : '1.0.0',
  license : 'BSD')

cne_rust_bindings_sources = files('bindings.c')

# Find cndp library dependency using pkg-config.
# PKG_CONFIG_PATH environment variable should be set to directory containing libcndp.pc file.
# If we cannot resolve cndp using pkg-config then use default include/library path.
cndp_dep = dependency('libcndp', required:false, method:'pkg-config')

if cndp_dep.found()
cndp_lib_dir = cndp_dep.get_pkgconfig_variable('libdir')
cndp_include_dir = cndp_dep.get_pkgconfig_variable('includedir')
else
# Use default library/include path.
cndp_lib_dir = '/usr/local/lib/x86_64-linux-gnu'
cndp_include_dir = '/usr/local/include'
endif

cndp_inc = include_directories(cndp_include_dir + '/cndp')
cndp_dep = declare_dependency(
    link_args : ['-L' + cndp_lib_dir, '-lcndp'],
    include_directories : cndp_inc)
bsd_dep = dependency('libbsd', required: true)
deps = [bsd_dep,cndp_dep]

cne_rust_bindings_libname = 'cne_rust_bindings'
lib_cndp_rust_bindings = library(cne_rust_bindings_libname, cne_rust_bindings_sources,
                                        install: false, dependencies: deps)
