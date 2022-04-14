#! /usr/bin/python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2020-2022 Intel Corporation

"""
Script to be used with the CNDP applications.
Allows the user send a json file to a CNDP application
"""

import sys
import socket
import os
import glob
import json

def handle_socket(path):
    """ Connect to socket and handle user input """
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    print("Connecting to " + path)
    try:
        sock.connect(path)
    except OSError:
        print("Error connecting to " + path)
        sock.close()
        return

    print('File: ' + file)
    f = open(file, 'rb')
    l = f.read(1024)
    while(True):
        if not l:
            break;
        sock.send(l)
        l = f.read(1024)

    print('Close File')
    f.close()

    sock.close()

file = sys.argv[1]
print('File: ', file)

# Path to sockets for processes run as a root user
for f in glob.glob('/var/run/cndp/config*'):
    handle_socket(f)
# Path to sockets for processes run as a regular user
for f in glob.glob('/run/user/%d/cndp/config*' % os.getuid()):
    handle_socket(f)
