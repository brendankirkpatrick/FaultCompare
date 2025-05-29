#!/usr/bin/python python3

from pathlib import Path
from typing import Set, Tuple, List
from collections import defaultdict
import time
import argparse

from capstone import CsInsn

from common import *

from cli import detect_target
from Parser import Instruction, Register, Address, IntegerLiteral, Location

from dynamic import disassemble_binary, faultflipper_parse
from static import faultarm_parse, DetectionType


def compare(args):
    # this file is created by faultflipper_parse

    asm_file = Path("out/disasm.s")
    bin_file = Path(args.binary)

    target = detect_target(bin_file)

    stime = time.perf_counter()
    # faultflipper returns (CsInsn, line_number)
    nop_inst, bit_inst, segfaults = faultflipper_parse(
        bin_file, target, run_nop=args.nop, run_bit=args.bitflip, num_cpus=4
    )
    ff_elapsed = time.perf_counter() - stime
    nop_list = sorted(nop_inst, key=lambda x: x[1])
    bit_list = sorted(bit_inst, key=lambda x: x[1])

    stime = time.perf_counter()
    # faultarm returns (Instruction, line_number, DetectionType)
    farm_inst = faultarm_parse(asm_file, target) if args.static else set()
    fa_elapsed = time.perf_counter() - stime

    finst_sort = sorted(farm_inst, key=lambda x: x[1])

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

    if args.report_individual:
        print_farm_inst(finst_sort)
        print_flip_inst(nop_list, bit_list)
    else:
        report_vuln_inline(nop_list, bit_list, finst_sort)

    if args.report_segfaults:
        report_segfaults(segfaults)


# report all vulns one line
def report_vuln_inline(nop_list: List, bit_list: List, static_list: List):
    nop_lookup = {ln: instruction for instruction, ln in nop_list}
    bit_lookup = {ln: instruction for instruction, ln in bit_list}

    # intermediate mapping: (ln, instruction) -> list of dtype
    _temp_lookup = defaultdict(list)
    for instruction, ln, dtype in static_list:
        _temp_lookup[(ln, instruction)].append(dtype)

    # final mapping: ln -> (instruction, list of dtype)
    static_lookup = {}
    for (ln, instruction), dtypes in _temp_lookup.items():
        # sort dtype so that it always appears in the same order
        static_lookup[ln] = (instruction, sorted(dtypes, key=lambda p: p.value))

    # merge sets together by line number
    fault_flip_union: List = sorted(
        set(nop_lookup.keys()) | set(bit_lookup.keys()) | set(static_lookup.keys())
    )

    console.print(
        f"[green]{'Line:':<8}{'Vulnerable Instructions:':<40}Vulnerability Types:"
    )

    for ln in fault_flip_union:
        console.print(f"{str(ln) + ": ":<8}", end="")

        # search nop -> bit -> static
        instruction = nop_lookup.get(ln) or bit_lookup.get(ln)
        if not instruction and ln in static_lookup:
            instruction = static_lookup[ln][0]

        instr_str = format_instruction(instruction)
        print(f"{instr_str:<40}", end="")  # breaks with console.print for some reason

        vuln_types = []
        if ln in static_lookup:
            vuln_types.extend(dtype.name for dtype in static_lookup[ln][1])
        if ln in nop_lookup:
            vuln_types.append("NOP")
        if ln in bit_lookup:
            vuln_types.append("BIT")
        console.print(" ".join(f"{v:<8}" for v in vuln_types))


# format instruction into printable f string
def format_instruction(instruction):
    if hasattr(instruction, "mnemonic") and hasattr(instruction, "op_str"):
        return f"{instruction.mnemonic} {instruction.op_str}"
    elif hasattr(instruction, "name") and hasattr(instruction, "arguments"):
        parts = []
        for arg in instruction.arguments:
            if isinstance(arg, (Register, Location)):
                parts.append(arg.name)
            elif isinstance(arg, IntegerLiteral):
                parts.append(f"#{hex(arg.value)}")
            else:
                parts.append(str(arg.value))
        return f"{instruction.name} {', '.join(parts)}"
    return "UNKNOWN"


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
        print(f"{line_number}: {instruction.name} ", end="")
        for offset in instruction.arguments:
            if type(offset) is Register or type(offset) is Location:
                print(f"{offset.name} ", end="")
            elif type(offset) is IntegerLiteral:
                print(f"#{hex(offset.value)} ", end="")
            else:
                print(f"{offset.value} ", end="")
        print(f"{dtype.name}")


# print out all of the lines that failed due to segfault (as opposed to returncode or stdout)
def report_segfaults(segfaults):
    console.print(f"[green]Error Line Numbers:[/green]\n{sorted(segfaults)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="FaultCompare",
        description="Dynamic/Static analysis for binary vulnerabilities",
    )

    parser.add_argument(
        "-b",
        "--binary",
        action="store",
        help="Path to the binary file to be analyzed",
        required=True,
    )
    parser.add_argument(
        "-n", "--nop", action="store_false", help="Disable NOP dynamic analysis"
    )
    parser.add_argument(
        "-f", "--bitflip", action="store_false", help="Disable BIT dynamic analysis"
    )
    parser.add_argument(
        "-s", "--static", action="store_false", help="Disable static analysis"
    )
    parser.add_argument(
        "-r",
        "--report-segfaults",
        action="store_true",
        help="Report lines resulting in SIGSEGV during dynamic analysis",
    )
    parser.add_argument(
        "-i",
        "--report-individual",
        action="store_true",
        help="Report vulnerable lines for static/dynamic analysis separately",
    )

    args = parser.parse_args()

    compare(args)
