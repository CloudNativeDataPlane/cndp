#!/usr/bin/bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2019-2023 Intel Corporation

# A simple script to build requirements.txt for all python files in CNDP

# check if pipreqs is installed
if ! which pipreqs &> /dev/null; then
    echo "pipreqs not found, please install it from pip."
    exit 1
fi

# find path from which we are running from
SOURCE="${BASH_SOURCE[0]}"
# cd into parent directory
cd "$(dirname "${SOURCE}")/../" || exit
# get SDK directory
SDK_DIR=$(pwd)
# store requirements file path
REQS_PATH="${SDK_DIR}/tools/requirements.txt"

# upgrade all packages that are already in requirements
echo "Upgrading packages..."
packages_list=$(grep -oE "^[^=]+" "${REQS_PATH}")
for p in $packages_list ;
do
    pip3 install --upgrade "$p"
done

# gather all Python files
FILES=$(find "$SDK_DIR" -name "*.py")
# gather directories where Python files reside
DIRS=$(for d in ${FILES} ; do dirname "$d" ; done)
# make sure each directory appears only once
UNIQUE_DIRS=$(echo "$DIRS" | tr ' ' '\n' | uniq)

# clear current requirements.txt
true > "${REQS_PATH}"

# we now have list of unique dirs, so let's dump everything into a single file
for uniq_d in $UNIQUE_DIRS
do
    echo "Scanning ${uniq_d}..."
    # create temporary file to which we will be writing
    tmpfname=$(mktemp)
    # create requirements.txt from Python directory
    pipreqs --savepath "${tmpfname}" "${uniq_d}" &> /dev/null
    # dump contents of newly created file to requirements.txt
    cat "${tmpfname}" >> "${REQS_PATH}"
    rm "${tmpfname}"
done

# make sure there are no duplicates in our requirements
cat "${REQS_PATH}" | \grep "\S" | sort -u | tee "${REQS_PATH}"
