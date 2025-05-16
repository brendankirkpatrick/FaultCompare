#!/usr/bin/python python3

from pathlib import Path
from typing import Set, Tuple, List
import time

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

    stime = time.perf_counter()
    # faultflipper returns (CsInsn, line_number)
    nop_inst, bit_inst = faultflipper_parse(bin_file, target, run_nop=True, run_bit=False)
    ff_elapsed = time.perf_counter() - stime

    stime = time.perf_counter()
    # faultarm returns (Instruction, line_number, DetectionType)
    farm_inst = faultarm_parse(asm_file, target)
    fa_elapsed = time.perf_counter() - stime

    finst_sort = sorted(farm_inst, key=lambda x: x[1])

    nop_list = sorted(nop_inst, key=lambda x: x[1])
    bit_list = sorted(bit_inst, key=lambda x: x[1])

    #print_farm_inst(finst_sort)
    #print_flip_inst(nop_list, bit_list)
    if ff_elapsed + fa_elapsed < 120:
        console.print(
            f"[magenta]Total Time Elapsed: FaultFlipper({ff_elapsed:.3f}s) + "
                f"FaultArm({fa_elapsed:.3f}s) = Total({ff_elapsed + fa_elapsed:.3f}s)[/magenta]"
        )
    else:
        console.print(
            f"[magenta]Total Time Elapsed: FaultFlipper({60 * ff_elapsed:.2f}s) + "
                f"FaultArm({60 * fa_elapsed:.2f}s) = Total({60*(ff_elapsed + fa_elapsed):.2f}s)[/magenta]"
        )

    report_vuln_inline(nop_list, bit_list, finst_sort)

# report all vulns one line
def report_vuln_inline(nop_list: List, bit_list: List, static_list: List):
    nop_lookup = {ln: instruction for instruction, ln in nop_list}
    bit_lookup = {ln: instruction for instruction, ln in bit_list}
    static_lookup = {ln: (instruction, dtype) for instruction, ln, dtype in static_list}
    fault_flip_union: List = sorted(set(nop_lookup.keys()) | 
                              set(bit_lookup.keys()) | 
                              set(static_lookup.keys())
                              )
    column_header1 = "Line:"
    column_header2 = "Vulnerable Instructions:"
    column_header3 = "Vulnerability Types:"
    console.print(f"[green]{column_header1:<8}{column_header2:<40}{column_header3}")
    for ln in fault_flip_union:
        # console.print doesnt work with op_str, have to use regular print???
        console.print(f"{str(ln) + ": ":<8}", end='')
        if ln in nop_lookup:
            instruction = nop_lookup[ln]
            print(f"{instruction.mnemonic + " " + instruction.op_str:<40}", end='')
        elif ln in bit_lookup:
            instruction = bit_lookup[ln]
            print(f"{instruction.mnemonic + " " + instruction.op_str:<40}", end='')
        elif ln in static_lookup:
            offset_str: str = ""
            instruction = static_lookup[ln][0]
            for offset in instruction.arguments:
                if type(offset) is Register or type(offset) is Location:
                    offset_str += str(offset.name)
                elif type(offset) is IntegerLiteral:
                    offset_str += str(f"#{hex(offset.value)}")
                else:
                    offset_str += str(offset.value)
            print(f"{instruction.name + " "  + offset_str:<40}", end='')

        if ln in static_lookup:
            console.print(f"{static_lookup[ln][1].name:<9}", end=' ')
        if ln in nop_lookup:
            console.print(f"{'NOP':<9}", end=' ')
        if ln in bit_lookup:
            console.print(f"{'BIT':<9}", end=' ')
        print()

# helper print fn
def print_flip_inst(nop_list: List, bit_list: List):
    nop_lookup = {ln: instruction for instruction, ln in nop_list}
    bit_lookup = {ln: instruction for instruction, ln in bit_list}
    fault_flip_union = sorted(set(nop_lookup.keys()) | set(bit_lookup.keys()))
    console.print(f"[green]FaultFlipper Instructions:")
    for ln in fault_flip_union:
        if ln in nop_lookup and ln in bit_lookup:
            # they are both the same so it doesnt matter which lookup I choose
            instruction = nop_lookup[ln]
            print(f"{ln}: {instruction.mnemonic} {instruction.op_str} NOP/BIT")
        elif ln in nop_lookup:
            instruction = nop_lookup[ln]
            print(f"{ln}: {instruction.mnemonic} {instruction.op_str} NOP")
        elif ln in bit_lookup:
            instruction = bit_lookup[ln]
            print(f"{ln}: {instruction.mnemonic} {instruction.op_str} BIT")
    print()

# helper print fn
def print_farm_inst(inst_list: list):
    console.print(f"[green]FaultArm Instructions:")
    for instruction, line_number, dtype in inst_list:
        print(f"{line_number}: {instruction.name} ", end='')
        for offset in instruction.arguments:
            if type(offset) is Register or type(offset) is Location:
                print(f"{offset.name} ", end='')
            elif type(offset) is IntegerLiteral:
                print(f"#{hex(offset.value)} ", end='')
            else:
                print(f"{offset.value} ", end='')
        print(f"{dtype.name}")


if __name__ == '__main__':
    compare()
