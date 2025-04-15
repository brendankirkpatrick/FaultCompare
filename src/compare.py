#!/usr/bin/python python3

# Add submodules to path for importing
import sys, os
sys.path.append(os.path.abspath(os.path.join('..', 'FaultArm')))
sys.path.append(os.path.abspath(os.path.join('..', 'FaultFlipper/src')))

# import packages from pip
from utils import console

# import FaultArm packages
from Parser import Parser
from Parser import Instruction
from Analyzer import Analyzer

# import FaultFlipper packages
from cli import disassemble_text_section

def compare():
    fr_asm_file = "guillermo_branch_complex_insecure.s"
# contains list of vulnerable instructions and their instruction number
    arm_inst : list[int] = FaultArmParse(fr_asm_file)

# FaultFlipper require the Binary file
    ff_bin_file = "test_bin"
    flip_inst : list[(str, str)] = FaultFlipperParse(ff_bin_file)

def FaultArmParse(file: str) -> list[int]:
# Parse data with Parser obj
    with console.status("Parsing file...", spinner="line"):
        try:
            parsed_data = Parser(file, console)
        except (FileNotFoundError, IsADirectoryError):
            console.print(f"[bright_red]Error: File {args.file[0]} not found or not valid.[/bright_red]")
            exit(1)
    console.log(f"Architecture Detected: [bright_yellow]{parsed_data.arch.name}[/bright_yellow]\n")

# Analyze data with Analyzer to get vulnerability results
    with console.status("Analyzing parsed data...", spinner="line"):
        analyzed_data = Analyzer(file, parsed_data, parsed_data.total_lines, "./out/", console)    

# Get list of vulnerable instructions and their respective line numbers
    vuln_instructions = list()

# Create quick function to insert all of the instructions into a flat list
    def instr_app(vul_instr_list):
        for instr_block in vul_instr_list:
            for instr in instr_block:
                vuln_instructions.append(instr)

    instr_app(analyzed_data.constant_detector.vulnerable_instructions)
    instr_app(analyzed_data.loop_detector.vulnerable_instructions)
    instr_app(analyzed_data.branchV2_detector.vulnerable_instructions)
    instr_app(analyzed_data.bypass_detector.vulnerable_set)

# create a list that stores the instruction number (relative to the first instruction)
    rel_num = list()
    for line_num, instr in enumerate(parsed_data.program):
        for vuln in vuln_instructions:
            if instr.line_number == vuln.line_number:
# have to check for instruction and ./@ chars since FaultFlipper disasm doesnt have those
                if type(temp) == Instruction:
                    if '.' not in temp.name and '@' not in temp.name:
                        rel_num.append(line_num)
    
    return rel_num

def FaultFlipperParse(binary_path: str) -> list[(str, str)]:
    disasm = disassemble_text_section(binary_path)

    address_list = []
    for instr in disasm:
        address_list.append(instr.address)
    # after running analysis, we should be able to see address from csv

    instruction_list = []
    return instruction_list


if __name__ == '__main__':
    compare()
