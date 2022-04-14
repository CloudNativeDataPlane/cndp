# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2022 Intel Corporation

project('jcfg parse rust helper', 'c',
  version : '1.0.0',
  license : 'BSD')

jcfg_parse_sources = files('parse-jsonc.c', 'stats.c', 'rust_helper.c')

# Find cndp library dependency using pkg-config.
# PKG_CONFIG_PATH environment variable should be set to directory containing libcndp.pc file.
cndp_dep = dependency('libcndp', method:'pkg-config')
cndp_lib_dir = cndp_dep.get_pkgconfig_variable('libdir')
cndp_include_dir = cndp_dep.get_pkgconfig_variable('includedir')
cndp_inc = include_directories(cndp_include_dir + '/cndp')

cndp_dep = declare_dependency(
    link_args : ['-lpthread', '-lbsd', '-L' + cndp_lib_dir, '-lcndp'],
    include_directories : cndp_inc)

jcfg_parse_libname = 'rust_' + 'jcfg_parse'
librust_jcfg_parse = both_libraries(jcfg_parse_libname, jcfg_parse_sources, install: false, dependencies: [cndp_dep])
