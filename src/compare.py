#!/usr/bin/python python3

from pathlib import Path
from typing import Set, Tuple, List

from capstone import CsInsn

from common import *

from cli import detect_target
from Parser import Instruction, Register, Address, IntegerLiteral, Location

from dynamic import disassemble_binary, faultflipper_parse
from static import faultarm_parse, DetectionType

def compare():
    # this file is created by faultflipper_parse
    asm_file = Path("out/disasm.s")
    bin_file = Path("test_files/pass_bin")

    target = detect_target(bin_file)

    # faultflipper returns (CsInsn, line_number)
    nop_inst, bit_inst = faultflipper_parse(bin_file, target, run_nop=True, run_bit=True)
    # faultarm returns (Instruction, line_number, DetectionType)
    farm_inst: Set[Tuple[Instruction, int, DetectionType]]  = faultarm_parse(asm_file, target)

    nop_list = sorted(nop_inst, key=lambda x: x[1])
    bit_list = sorted(bit_inst, key=lambda x: x[1])
    print_flip_inst(nop_list, bit_list)

    finst_sort = sorted(farm_inst, key=lambda x: x[1])
    print_farm_inst(finst_sort)

# helper print fn
def print_flip_inst(nop_list: List, bit_list: List):
    nop_lookup = {ln: instruction for instruction, ln in nop_list}
    bit_lookup = {ln: instruction for instruction, ln in bit_list}
    fault_flip_union = sorted(set(nop_lookup.keys()) | set(bit_lookup.keys()))
    console.print(f"[magenta]FaultFlipper Instructions:")
    for ln in fault_flip_union:
        if ln in nop_lookup and ln in bit_lookup:
            # they are both the same so it doesnt matter which lookup I choose
            console.print(f"{ln}: [green]{nop_lookup[ln].mnemonic} {nop_lookup[ln].op_str} BIT/NOP")
        elif ln in nop_lookup:
            console.print(f"{ln}: [green]{nop_lookup[ln].mnemonic} {nop_lookup[ln].op_str} NOP")
        elif ln in bit_lookup:
            console.print(f"{ln}: [green]{bit_lookup[ln].mnemonic} {bit_lookup[ln].op_str} BIT")
    print()

# helper print fn
def print_farm_inst(inst_list: list):
    console.print(f"[magenta]FaultArm Instructions:")
    for instruction, line_number, dtype in inst_list:
        console.print(f"{line_number}: [green]{instruction.name} ", end='')
        for offset in instruction.arguments:
            if type(offset) is Register or type(offset) is Location:
                console.print(f"[green]{offset.name} ", end='')
            else:
                console.print(f"{offset.value} ", end='')
        console.print(f"[green]{dtype}")


if __name__ == '__main__':
    compare()
