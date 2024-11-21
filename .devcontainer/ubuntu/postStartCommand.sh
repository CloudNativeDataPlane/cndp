#! /bin/sh -e
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2024 Red Hat, Inc.
pip install pre-commit
pre-commit install
make clean
