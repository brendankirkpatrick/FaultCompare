#!/usr/bin/python python3

from pathlib import Path

# import FaultArm for console file
import sys, os
sys.path.append(os.path.abspath(os.path.join('.', 'FaultArm')))
from utils import console

from dynamic import faultflipper_parse
from static import faultarm_parse

def compare():
    # FaultFlipper require the Binary file
    ff_bin_file = Path("test_files/pass_bin")
    flip_inst = faultflipper_parse(ff_bin_file)
    dynamic_set : Set = {lnum[1] for lnum in flip_inst}

    # resultant file from disasm for FaultFlipper
    fr_asm_file = str("./out/disasm.s")
    #fr_asm_file = str("./test_files/pass_asm.s")

    # contains list of vulnerable instructions and their instruction number
    static_set : set[int] = faultarm_parse(fr_asm_file)

    console.print(f"[green]Static:[/green] {sorted(static_set)}\n")
    console.print(f"[magenta]Dynamic[/magenta]: {sorted(dynamic_set)}\n")
    console.print(f"[green]Unique Static:[/green] {sorted(static_set - dynamic_set)}\n")
    console.print(f"[magenta]Unique Dynaimc:[/magenta] {sorted(dynamic_set - static_set)}\n")

if __name__ == '__main__':
    compare()
