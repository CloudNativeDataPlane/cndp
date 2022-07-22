#!/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2022 Intel Corporation

# A simple script to help build CNDP using meson/ninja tools.
# The script also creates an installed directory called usr/local.
# The install directory will contain all of the includes and libraries
# for external applications to build and link with CNDP.
#
# using 'cne-build.sh help' or 'cne-build.sh -h' or 'cne-build.sh --help' to see help information.
#

currdir=`pwd`
script_dir=$(cd "${BASH_SOURCE[0]%/*}" && pwd -P)
sdk_dir="${CNE_SDK_DIR:-${script_dir%/*}}"
target_dir="${CNE_TARGET_DIR:-usr/local}"
build_dir="${CNE_BUILD_DIR:-${currdir}/builddir}"
install_path="${CNE_DEST_DIR:-${currdir}}"

export PKG_CONFIG_PATH="${PKG_CONFIG_PATH:-/usr/lib64/pkgconfig}"

buildtype="release"
static=""
coverity=""
configure=""

if [[ "${build_dir}" = /* ]]; then
    # absolute path to build dir. Don't prepend workdir.
    build_path=$build_dir
else
    build_path=${currdir}/$build_dir
fi
if [[ ! "${install_path}" = /* ]]; then
    # relative path for install path detected
    # prepend with currdir
    install_path=${currdir}/${install_path}
fi
if [[ "${target_dir}" = .* ]]; then
    echo "target_dir starts with . or .. if different install prefix required then use CNE_DEST_DIR instead";
    exit 1;
fi
if [[ "${target_dir}" = /* ]]; then
    echo "target_dir absolute path detected removing leading '/'"
    export target_dir=${target_dir##/}
fi
target_path=${install_path%/}/${target_dir%/}

echo "Build environment variables and paths:"
echo "  CNE_SDK_DIR     : "$sdk_dir
echo "  CNE_TARGET_DIR  : "$target_dir
echo "  CNE_BUILD_DIR   : "$build_dir
echo "  CNE_DEST_DIR    : "$install_path
echo "  PKG_CONFIG_PATH : "$PKG_CONFIG_PATH
echo "  build_path      : "$build_path
echo "  target_path     : "$target_path
echo ""

function run_meson() {
    btype="-Dbuildtype="$buildtype
    meson $configure $static $coverity $btype --prefix="/$target_dir" "$build_path" "$sdk_dir"
}

function ninja_build() {
    echo ">>> Ninja build in '"$build_path"' buildtype='"$buildtype"'"

    if [[ -d $build_path ]] || [[ -f $build_path/build.ninja ]]; then
        # add reconfigure command if meson dir already exists
        configure="configure"
        # sdk_dir must be empty if we're reconfiguring
        sdk_dir=""
    fi
    run_meson

    ninja -C "$build_path"

    if [[ $? -ne 0 ]]; then
        return 1;
    fi
    return 0
}

function ninja_build_docs() {
    echo ">>> Ninja build documents in '"$build_path"'"

    if [[ ! -d $build_path ]] || [[ ! -f $build_path/build.ninja ]]; then
        run_meson
    fi

    ninja -C $build_path doc

    if [[ $? -ne 0 ]]; then
        return 1;
    fi
    return 0
}

function build_rust_apps() {
    echo ">>> Build rust applications"
    # Check if Cargo is installed.
    command -v cargo &> /dev/null
    if [[ $? -ne 0 ]]; then
        echo "Cargo not found.Install Cargo"
        return 1
    fi
    # Build rust applications
    if [[ -d ${currdir}/lang/rs ]]; then
        cd ${currdir}/lang/rs
        cargo_build_rust_app
    fi
}

function cargo_build_rust_app() {
    if [ "$buildtype" == "release" ]; then
        cargo build --release
    else
        cargo build
    fi

    if [[ $? -ne 0 ]]; then
        return 1;
    fi
    return 0
}

function clean_rust_apps() {
    echo ">>> Clean rust applications"
    # Check if Cargo is installed.
    command -v cargo &> /dev/null
    if [[ $? -ne 0 ]]; then
        echo "Cargo not found.Install Cargo"
        return 1
    fi
    # Clean rust applications.
    if [[ -d ${currdir}/lang/rs ]]; then
        cd ${currdir}/lang/rs
        cargo_clean_rust_app
    fi
}

function cargo_clean_rust_app() {
    cargo clean -v
    if [[ $? -ne 0 ]]; then
        return 1;
    fi
    return 0
}


ninja_install() {
    echo ">>> Ninja install to '"$target_path"'"

    if [[ $verbose = true ]]; then
        DESTDIR=$install_path ninja -C $build_path install
    else
        DESTDIR=$install_path ninja -C $build_path install > /dev/null
    fi

    if [[ $? -ne 0 ]]; then
        echo "*** Install failed!!"
        return 1;
    fi
    return 0
}

ninja_uninstall() {
    echo ">>> Ninja uninstall to '"$target_path"'"

    if [[ $verbose = true ]]; then
        DESTDIR=$install_path ninja -C $build_path uninstall
    else
        DESTDIR=$install_path ninja -C $build_path uninstall > /dev/null
    fi

    if [[ $? -ne 0 ]]; then
        echo "*** Uninstall failed!!"
        return 1;
    fi
    return 0
}

usage() {
    echo " Usage: Build CNDP using Meson/Ninja tools"
    echo "  ** Must be in the top level directory for CNDP"
    echo "     This tool is in tools/cne-build.sh, but use 'make' which calls this script"
    echo "     Use 'make' to build CNDP as it allows for multiple targets i.e. 'make clean debug'"
    echo ""
    echo "     CNE_SDK_DIR    - CNDP source directory path (default: current working directory)"
    echo "     CNE_TARGET_DIR - Target directory for installed files (default: usr/local)"
    echo "     CNE_BUILD_DIR  - Build directory name (default: builddir)"
    echo "     CNE_DEST_DIR   - Destination directory (default: current working directory)"
    echo ""
    echo "  cne-build.sh     - create the 'build_dir' directory if not present and compile CNDP"
    echo "                     If the 'build_dir' directory exists it will use ninja to build CNDP"
    echo "                     without running meson unless one of the meson.build files were changed"
    echo "    -v             - Enable verbose output"
    echo "    build          - build CNDP using the 'build_dir' directory"
    echo "    static         - build CNDP static using the 'build_dir' directory, 'make static build'"
    echo "    debug          - turn off optimization, may need to do 'clean' then 'debug' the first time"
    echo "    debugopt       - turn optimization on with -O2, may need to do 'clean' then 'debugopt'"
    echo "                     the first time"
    echo "    clean          - remove the 'build_dir' directory then exit"
    echo "    install        - install the includes/libraries into 'target_dir' directory"
    echo "    uninstall      - uninstall the includes/libraries from 'target_dir' directory"
    echo "    coverity       - (internal) build using coverity tool"
    echo "    docs           - create the document files"
    echo "    rust-app       - Build Rust application"
    echo "    rust-app-clean - Clean Rust application"
    exit
}

verbose=false

for cmd in $@
do
    case "$cmd" in
    'help' | '-h' | '--help')
        usage
        ;;

    '-v' | '--verbose')
        verbose=true
        ;;

    'static')
        echo ">>> Static  build in '"$build_path"'"
        static="-Ddefault_library=static"
        ;;

    'build')
        echo ">>> Release build in '"$build_path"'"
        ninja_build
        ;;

    'coverity')
        echo ">>> Build for Coverity in '"$build_path"'"
        coverity="-Dcoverity=true"
        ninja_build
        ;;

    'debug')
        echo ">>> Debug build in '"$build_path"'"
        buildtype="debug"
        ninja_build
        ;;

    'debugopt')
        echo ">>> Debug Optimized build in '"$build_path"'"
        buildtype="debugoptimized"
        ninja_build
        ;;

    'clean')
        echo "*** Removing '"$build_path"' directory"
        rm -fr $build_path
        ;;

    'uninstall')
        echo "*** Uninstalling '"$target_path"' directory"
        ninja_uninstall
        exit
        ;;

    'install')
        echo ">>> Install the includes/libraries into '"$target_path"' directory"
        ninja_install
        ;;

    'docs')
        echo ">>> Create the documents in '"$build_path"' directory"
        ninja_build_docs
        ;;

    'rust-app')
        echo ">>> Build Rust application. This should be run after building and installing CNDP"
        build_rust_apps
        ;;

    'rust-app-clean')
        echo ">>> Clean Rust application"
        clean_rust_apps
        ;;

    *)
        if [[ $# -gt 0 ]]; then
            usage
        else
            echo ">>> Build and install CNDP"
            ninja_build && ninja_install
        fi
        ;;
    esac
done
