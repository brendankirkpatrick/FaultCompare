#!/usr/bin/python python3

from pathlib import Path

# Add submodules to path for importing
import sys, os
sys.path.append(os.path.abspath(os.path.join('..', 'FaultArm')))
sys.path.append(os.path.abspath(os.path.join('..', 'FaultFlipper/src')))

# import packages from pip
from utils import console
import pandas as pd

# import FaultArm packages
from Parser import Parser
from Parser import Instruction
from Analyzer import Analyzer

# import FaultFlipper packages
from cli import *


def compare():
    fr_asm_file = str("./guillermo_compiler_complex_insecure.s")
# contains list of vulnerable instructions and their instruction number
    arm_inst : list[int] = faultarm_parse(fr_asm_file)

# FaultFlipper require the Binary file
    ff_bin_file = Path("test_bin")
    flip_inst = faultflipper_parse(ff_bin_file, 8)
    for insn, line_num in flip_inst:
        print(f"{insn.mnemonic} {insn.op_str}\ton line {line_num}")


def faultarm_parse(file: str) -> list[int]:
# Parse data with Parser obj
    with console.status("Parsing file...", spinner="line"):
        try:
            parsed_data = Parser(file, console)
        except (FileNotFoundError, IsADirectoryError):
            console.print(f"[bright_red]Error: File {file} not found or not valid.[/bright_red]")
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
# must check for instruction and ./@ chars since FaultFlipper disasm doesnt have those
                if type(vuln) == Instruction:
                    if '.' not in vuln.name and '@' not in vuln.name:
                        rel_num.append(line_num)
    
    return rel_num

def extract_bit_exp(result):
    other_returncodes = [
        ("critical_code_ran", 0),
        ("critical_code_did_not_run", 97),
        ("failed_to_run", -900),
    ]
    for (
        out_file,
        returncode,
        inst,
        common,
        target,
        stdout,
        stderr,
        i,
    ) in result:
        if stdout.contains(common.expected_stdout) and returncode == common.expected_returncode:
            return True
    return False


def faultflipper_parse(binary_path: Path, num_cpus: int) -> pd.DataFrame:
    output_path = Path("out")
    common = CommandParameters(binary_path, output_path, "5", "Access denied.", 0)
    common.out_dir.mkdir(exist_ok=True)

    binary = lief.parse(common.program_file)

    text_section = binary.get_section(".text")
    if not text_section:
        raise ValueError(".text section not found in the binary.")

    target = detect_target(common.program_file)

    match target:
        case Target.X86_64:
            md = Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        case Target.RISCV:
            md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)
        case Target.ARM_64:
            md = Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        case Target.ARM_32:
            md = Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        case _:
            raise Exception("Unsupported file type")
    disasm = list(md.disasm(text_section.content, text_section.virtual_address))

    # wrapper function to allow extracting instr from future
    def exp_wrapper(func):
        def wrapper(*args, **kwargs):
            instn = args[1] if args else None
            instn_count = args[-1] if args else None
            return (func(*args[:-1], **kwargs), instn, instn_count)
        return wrapper
    # creates wrapper function to pass to future
    para_bit_args = exp_wrapper(bit_para_run_helper)

    # list of instructions to return from fn
    instructions = []

    max_workers = max(
        1, num_cpus // 2
    )  # avoid 0 in case cpu_count() returns None
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for inst_count, inst in enumerate(disasm):
            future = executor.submit(para_bit_args, common, inst, target, inst_count)
            futures.append(future)

        total_tasks = len(futures)

        with alive_bar(total_tasks, title="Processing tasks") as bar:
            for future in as_completed(futures):
                result = future.result()
                if extract_bit_exp(result[0]):
                    instructions.append(result[1])
                bar()  # increment the progress bar by 1
                for binary in result[0]: 
                    os.remove(binary[0]) # binary is tuple where [0] is out_file

    return instructions


if __name__ == '__main__':
    compare()
