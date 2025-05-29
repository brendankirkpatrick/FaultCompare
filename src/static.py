#!/usr/bin/python python3

from pathlib import Path
from typing import Set, Tuple
from enum import Enum

from common import *

# import FaultArm packages
from Parser import Parser, Instruction, Architecture, Register, Location
from Analyzer import Analyzer


class DetectionType(Enum):
    Constant = 0
    BranchV2 = 1
    Loop = 2
    Bypass = 3


# parse FaultArm ASM file and return set of vulnerable instructions
def faultarm_parse(file: Path, target: Target) -> Set[Tuple]:
    # parse data with Parser obj
    # get list of vulnerable instructions and their respective line numbers
    vuln_instructions = list()
    rel_num = set()

    analyzer, program_file = create_analyzer(str(file), target)

    # function to insert all of the instructions into a flat list
    def instruction_append(vul_instr_list, dtype: DetectionType):
        for instr_block in vul_instr_list:
            for instr in instr_block:
                vuln_instructions.append((instr, dtype))

    # append each list of vulnerable instructions to our list
    instruction_append(
        analyzer.constant_detector.vulnerable_instructions, DetectionType.Constant
    )
    instruction_append(
        analyzer.loop_detector.vulnerable_instructions, DetectionType.Loop
    )
    instruction_append(
        analyzer.branchV2_detector.vulnerable_instructions, DetectionType.BranchV2
    )
    instruction_append(analyzer.bypass_detector.vulnerable_set, DetectionType.Bypass)

    vuln_lines = [(vuln.line_number, dtype) for vuln, dtype in vuln_instructions]

    # loop through our instructions and extract relative line numbers for instructions
    instruction_count = 0
    for instr in program_file:
        if (
            type(instr) == Instruction
            and "." not in instr.name
            and "@" not in instr.name
        ):
            instruction_count += 1
            # if instruction is vulnerable, add the line to our set
            for ln, dtype in vuln_lines:
                if instr.line_number == ln:
                    rel_num.add((instr, instruction_count, dtype))

    return rel_num


# create Parser/Analyzer
def create_analyzer(file: str, target) -> Analyzer:
    with console.status("Parsing file...", spinner="line"):
        try:
            parsed_data = Parser(file, console)
            architecture = Architecture(line=None, instruction=None)
            architecture.name = match_target(target)
            architecture.is_determined = True
            parsed_data.arch = architecture
        except (FileNotFoundError, IsADirectoryError):
            console.print(
                f"[bright_red]Error: File {file} not found or not valid.[/bright_red]"
            )
            exit(1)

    # analyze data with Analyzer to get vulnerability results
    with console.status("Analyzing parsed data...", spinner="line"):
        analyzed_data = Analyzer(
            file, parsed_data, parsed_data.total_lines, "./out/", console
        )
    return analyzed_data, parsed_data.program


# set target according to detected target
def match_target(target: Target) -> str:
    match target:
        case Target.X86_64:
            # this doesnt work atm, need upstream changes from FaultArm
            return "x86"
        case Target.RISCV:
            raise Exception("Unsupported file type")
        case Target.ARM_64:
            return "arm"
        case Target.ARM_32:
            return "arm"
        case _:
            raise Exception("Unsupported file type")
