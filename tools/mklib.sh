#!/bin/bash

outfile=$1
shift 1

echo "GROUP (" $* ")" > /tmp/$outfile
