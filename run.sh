#!/bin/bash

FAULT_ARM_DEFAULT_FILE="FaultArm/dataset/op_0/manual/guillermo_branch_complex_insecure.s"

if $# -ne 0; then
    ./FaultArm/venv/bin/python FaultArm/main.py "$@"
else
    ./FaultArm/venv/bin/python FaultArm/main.py "$FAULT_ARM_DEFAULT_FILE"
fi

pixi exec python FaultFlipper/src/cli.py --help
