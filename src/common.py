#!/usr/bin/python python3

# Organize common imports to prevent clutter in other files

import sys, os
sys.path.append(os.path.abspath(os.path.join('.', 'FaultArm')))
sys.path.append(os.path.abspath(os.path.join('.', 'FaultFlipper/src')))

from binary_tools import Target

# important to note that for some reason rich is unable to print disassembly to console
# I suspect that it might be some encoding issue? but I honstly have no idea
# using print() instead just works
from utils import console
