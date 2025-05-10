#!/bin/bash

comp_f=$1
bin_f=$2

EXPECTED_ARGS=2
if [ $# -ne $EXPECTED_ARGS ]; then
    echo "Invalid number of arguments. Expected: $EXPECTED_ARGS"
    exit 1
fi

# compile file
arm-linux-gnueabi-gcc $comp_f -o $bin_f 

read -p "Run [y/n]? " run

answer=${run,,}
if [[ "$run" == "y" ]]; then
    echo "RUNNING FILE"
# run file
    qemu-arm-static -L /usr/arm-linux-gnueabi $bin_f
fi
