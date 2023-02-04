# Copyright (c) 2021-2023 Intel Corporation
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

unset (CNE_LIB CACHE)
find_path(CNE_INCLUDE_DIR PATHS ENV CNDP_INSTALL_DIR PATH_SUFFIXES include/cndp NAMES cne.h)

vpp_plugin_find_library(cndp CNE_LIB "libcndp.a" PATHS ENV CNDP_INSTALL_DIR PATH_SUFFIXES lib/x86_64-linux-gnu)
vpp_plugin_find_library(cndp BPF_LIB "libbpf.a" PATHS /usr/lib64 )

if (NOT CNE_INCLUDE_DIR)
  message(WARNING "-- CNDP headers not found - cndp plugin disabled" ${CNDP_INSTALL_DIR})
  return()
endif()

include_directories (${CNE_INCLUDE_DIR})
list(APPEND CNE_LINK_LIBRARIES ${CNE_LIB})
string_append(CNE_LINK_FLAGS "-Wl,--whole-archive,${CNE_LIB},--no-whole-archive")

list(APPEND CNE_LINK_LIBRARIES ${BPF_LIB})
string_append(CNE_LINK_FLAGS "-Wl,--whole-archive,${BPF_LIB},--no-whole-archive")

vpp_plugin_find_library(cndp BSDLIB "libbsd.so")
list(APPEND CNE_LINK_LIBRARIES ${BSDLIB})

add_vpp_plugin(cndp
  SOURCES
  cndp_elog.h
  device.c
  cndp.h
  cli.c
  output.c
  format.c
  input.c

  LINK_FLAGS
  "${CNE_LINK_FLAGS}"

  LINK_LIBRARIES
  ${CNE_LINK_LIBRARIES}

  COMPONENT vpp-plugin-cndp
)
