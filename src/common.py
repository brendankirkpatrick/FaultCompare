#!/usr/bin/python python3

# Organize common imports to prevent clutter in other files

import sys, os
sys.path.append(os.path.abspath(os.path.join('.', 'FaultArm')))
sys.path.append(os.path.abspath(os.path.join('.', 'FaultFlipper/src')))

from binary_tools import Target
from utils import console
