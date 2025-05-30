#!/usr/bin/python python3

from pathlib import Path
from typing import Set, Tuple, List
from collections import defaultdict
import time
import argparse

from capstone import CsInsn
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

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
    nop_inst, bit_inst, segfaults, num_instructions = faultflipper_parse(
        bin_file,
        target,
        run_nop=not args.disable_nop,
        run_bit=not args.disable_bitflip,
        num_cpus=4,
    )
    ff_elapsed = time.perf_counter() - stime
    nop_list = sorted(nop_inst, key=lambda x: x[1])
    bit_list = sorted(bit_inst, key=lambda x: x[1])

    stime = time.perf_counter()
    # faultarm returns (Instruction, line_number, DetectionType)
    farm_inst = faultarm_parse(asm_file, target) if not args.disable_static else set()
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

    if args.create_graph:
        if args.disable_bitflip or args.disable_nop or args.disable_static:
            console.print(
                f"[red]Error:[/red] Unable to create graph. Must have static, bitflip, and nop enabled."
            )
        else:
            create_plot(nop_list, bit_list, finst_sort, segfaults, num_instructions)


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


# create matplotlib plot
def create_plot(nop_list, bit_list, static_list, segfaults, num_instructions):
    # Configuration
    dtypes = ["Bypass", "Loop", "Constant", "Branch", "NOP", "BIT"]
    colors = {
        "Both": "#7f2a19",  # blue
        "SIGSEGV": "#f6b26b",  # orange
        "Vulnerable": "#e66c2c",  # red
        "normal": "#e0e0e0",  # gray (default background)
    }

    nops = [ln for _, ln in nop_list]
    bits = [ln for _, ln in bit_list]
    constants = [ln for _, ln, dtype in static_list if dtype == DetectionType.Constant]
    branches = [ln for _, ln, dtype in static_list if dtype == DetectionType.BranchV2]
    loops = [ln for _, ln, dtype in static_list if dtype == DetectionType.Loop]
    bypasses = [ln for _, ln, dtype in static_list if dtype == DetectionType.Bypass]

    # Rows to in table consisting of sublists
    vulns = [bypasses, loops, constants, branches, nops, bits]

    # Plotting
    fig, ax = plt.subplots(figsize=(14, 8))
    y_pos = np.arange(len(dtypes))
    height = 0.8

    plt.rcParams.update(
        {
            "font.size": 14,  # Base font size
            "axes.titlesize": 30,  # Title
            "axes.labelsize": 20,  # X and Y labels
        }
    )

    for i, row in enumerate(vulns):
        for j in range(num_instructions):
            if j in row:
                if j in segfaults:
                    ax.barh(
                        i,
                        1,
                        left=j,
                        height=height,
                        color=colors["Both"],
                        edgecolor="none",
                    )
                else:
                    ax.barh(
                        i,
                        1,
                        left=j,
                        height=height,
                        color=colors["Vulnerable"],
                        edgecolor="none",
                    )
            elif j in segfaults:
                ax.barh(
                    i,
                    1,
                    left=j,
                    height=height,
                    color=colors["SIGSEGV"],
                    edgecolor="none",
                )
            else:
                ax.barh(
                    i,
                    1,
                    left=j,
                    height=height,
                    color=colors["normal"],
                    edgecolor="none",
                )

    # Formatting
    ax.set_yticks(y_pos)
    ax.set_yticklabels([f"{d}" for d in dtypes])
    ax.tick_params(axis="y", labelsize=20)
    ax.invert_yaxis()  # Like in the image

    tick_interval = 30
    xticks = list(range(0, num_instructions + 1, tick_interval))
    xtick_labels = [str(i + 1) for i in xticks]
    ax.set_xticks(xticks)
    ax.set_xticklabels(xtick_labels)

    ax.set_xlabel("Line Number", fontsize=20)
    ax.set_title("Vulnerable Instructions")

    legend_handles = [
        mpatches.Patch(color=colors["Both"], label="SIGSEGV and Vulnerable Output"),
        mpatches.Patch(color=colors["Vulnerable"], label="Vulnerable Output"),
        mpatches.Patch(color=colors["SIGSEGV"], label="SIGSEGV"),
    ]
    ax.legend(handles=legend_handles, loc="lower right")

    plt.tight_layout()
    plt.savefig("out/graph.png", dpi=300, bbox_inches="tight")
    plt.show()


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
        "-n",
        "--disable-nop",
        action="store_true",
        help="Disable dynamic analysis for NOP",
    )
    parser.add_argument(
        "-f",
        "--disable-bitflip",
        action="store_true",
        help="Disable dynamic analysis for BIT",
    )
    parser.add_argument(
        "-s",
        "--disable-static",
        action="store_true",
        help="Disable all static analysis",
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
    parser.add_argument(
        "-g",
        "--create-graph",
        action="store_true",
        help="Create vulnerability graph",
    )

    args = parser.parse_args()

    compare(args)
