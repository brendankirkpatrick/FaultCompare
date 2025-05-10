#!/bin/bash

BIN_FILE=$1
CORE_FILE=$2

EXPECTED_ARGS=2
if [ $# -ne $EXPECTED_ARGS ]; then
    echo "Invalid number of arguments. Expected: $EXPECTED_ARGS"
    exit 1
fi

# run gdb-multiarch to analyze coredump
gdb-multiarch -iex 'set sysroot /usr/arm-linux-gnueabi' out/$BIN_FILE $CORE_FILE 
