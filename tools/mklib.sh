#!/bin/bash

outdir=$1
outfile=$2
shift 2

echo "GROUP (" "$*" ")" > "$outdir/$outfile"
