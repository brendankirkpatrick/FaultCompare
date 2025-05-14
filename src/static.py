#!/usr/bin/python python3

from typing import Set

# Add submodules to path for importing
import sys, os
sys.path.append(os.path.abspath(os.path.join('.', 'FaultArm')))

from utils import console

# import FaultArm packages
from Parser import Parser
from Parser import Instruction
from Parser import Architecture
from Analyzer import Analyzer

# parse FaultArm ASM file and return set of vulnerable instructions
def faultarm_parse(file: str) -> Set:
    # parse data with Parser obj
    # get list of vulnerable instructions and their respective line numbers
    vuln_instructions = list()
    rel_num = set()

    analyzer, program_file = create_analyzer(file)

    # function to insert all of the instructions into a flat list
    def instruction_append(vul_instr_list):
        for instr_block in vul_instr_list:
            for instr in instr_block:
                vuln_instructions.append(instr)

    # append each list of vulnerable instructions to our list
    instruction_append(analyzer.constant_detector.vulnerable_instructions)
    instruction_append(analyzer.loop_detector.vulnerable_instructions)
    instruction_append(analyzer.branchV2_detector.vulnerable_instructions)
    instruction_append(analyzer.bypass_detector.vulnerable_set)

    vuln_lines = [vuln.line_number for vuln in vuln_instructions]

    # loop through our instructions and extract relative line numbers for instructions
    instruction_count = 0
    for instr in program_file:
        if type(instr) == Instruction and '.' not in instr.name and '@' not in instr.name:
            instruction_count += 1
            # if instruction is vulnerable, add the line to our list
            if instr.line_number in vuln_lines:
                rel_num.add(instruction_count)

    return rel_num

# create Parser/Analyzer 
def create_analyzer(file: str) -> Analyzer:
    with console.status("Parsing file...", spinner="line"):
        try:
            parsed_data = Parser(file, console)
            architecture = Architecture(line=None, instruction=None) 
            architecture.name = "arm"
            architecture.is_determined = True
            parsed_data.arch = architecture
        except (FileNotFoundError, IsADirectoryError):
            console.print(f"[bright_red]Error: File {file} not found or not valid.[/bright_red]")
            exit(1)
    console.log(f"Architecture Detected: [bright_yellow]{parsed_data.arch.name}[/bright_yellow]\n")

    # analyze data with Analyzer to get vulnerability results
    with console.status("Analyzing parsed data...", spinner="line"):
        analyzed_data = Analyzer(file, parsed_data, parsed_data.total_lines, "./out/", console)    
    return analyzed_data, parsed_data.program

