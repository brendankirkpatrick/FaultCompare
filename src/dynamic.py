#!/usr/bin/python python3

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, Tuple, List
from enum import Flag, auto

from capstone import Cs, CsInsn
import capstone
import lief
from alive_progress import alive_bar

from common import *
from cli import *
from enums import LinuxExitCodes


# runs FaultFlipper analysis on binary file, outputs a set of vulnerable line numbers
def faultflipper_parse(
    binary: Path, target: Target, num_cpus=1, run_nop=True, run_bit=False
) -> Tuple:
    run_paramaters = generate_cmd_param(binary)
    disasm = disassemble_binary(binary, target)

    bit_helper = exp_wrapper(bit_para_run_helper)
    nop_helper = exp_wrapper(nop_para_run_helper)

    nop_instructions, bit_instructions, segfaults = run_parallel_analysis(
        disasm,
        target,
        run_paramaters,
        num_cpus,
        run_nop,
        run_bit,
        bit_helper,
        nop_helper,
    )

    return nop_instructions, bit_instructions, set(segfaults)


# wraps our run helper function calls to capture more data
def exp_wrapper(func):
    def wrapper(*args, **kwargs):
        instn = args[1] if args else None
        instn_count = args[-1] if args else None
        return (func(*args[:-1], **kwargs), instn, instn_count)

    return wrapper


# defaults for CommandParameters values
def generate_cmd_param(binary_path: Path):
    output_path = Path("out")
    output_path.mkdir(exist_ok=True)

    # value fed to stdin for binary
    prog_stdin = "nope\n"

    # values to detect in program output
    # if a value is detected, mark as vulnerable
    stdout_detect = "Correct\n"
    ret_detect = 0

    timeout_seconds = 0.5
    return CommandParameters(
        binary_path,
        output_path,
        prog_stdin,
        stdout_detect,
        ret_detect,
        timeout=timeout_seconds,
    )


# create disassembly from as list of CsInsn
def disassemble_binary(program_file, target) -> List:
    binary = lief.parse(str(program_file))

    text_section = binary.get_section(".text")
    if not text_section:
        raise ValueError(".text section not found in the binary.")

    md = get_disassembler(target)
    disasm = list(md.disasm(text_section.content, text_section.virtual_address))

    write_disasm(disasm)

    return disasm


# detection types
def get_disassembler(target):
    match target:
        case Target.X86_64:
            return Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        case Target.RISCV:
            return Cs(
                capstone.CS_ARCH_RISCV,
                capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC,
            )
        case Target.ARM_64:
            return Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        case Target.ARM_32:
            return Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        case _:
            raise Exception("Unsupported file type")


# write disassembly to file
def write_disasm(disasm: List):
    output_file = Path("out/disasm.s")
    with output_file.open("w") as f:
        for insn in disasm:
            f.write(f"{insn.mnemonic}\t{insn.op_str}\n")


class ErrorStatus(Flag):
    NONE = 0
    SIGSEGV = auto()
    RETURN_CODE = auto()
    STDOUT = auto()


# determines whether stdout or returncode is in bit output
def extract_bit_exp(result):
    triggered = ErrorStatus.NONE
    for (
        out_file,
        returncode,
        inst,
        run_parameters,
        target,
        stdout,
        stderr,
        i,
    ) in result:
        if returncode == LinuxExitCodes.EX_SIGSEGV:
            triggered |= ErrorStatus.SIGSEGV
        if stdout in run_parameters.expected_stdout and len(stdout) > 1:
            triggered |= ErrorStatus.STDOUT
        if returncode == run_parameters.expected_returncode:
            triggered |= ErrorStatus.RETURN_CODE
    return triggered


# determines whether stdout or returncode is in nop output
def extract_nop_exp(result):
    out_file, returncode, inst, run_parameters, target, stdout, stderr = result
    triggered = ErrorStatus.NONE
    if returncode == LinuxExitCodes.EX_SIGSEGV:
        triggered |= ErrorStatus.SIGSEGV
    if stdout in run_parameters.expected_stdout and len(stdout) > 1:
        triggered |= ErrorStatus.STDOUT
    if returncode == run_parameters.expected_returncode:
        triggered |= ErrorStatus.RETURN_CODE
    return triggered


# run nop and bit analysis while wrapping return values to extract line numbers
def run_parallel_analysis(
    disasm, target, run_parameters, num_cpus, run_nop, run_bit, bit_helper, nop_helper
):
    nop_instructions = set()
    bit_instructions = set()
    segfaults = list()
    max_workers = max(1, num_cpus // 2)

    # submit tasks to thread pool for nop/bit while wrapping responses
    nop_futures, bit_futures = submit_tasks(
        disasm, target, run_parameters, run_nop, run_bit, nop_helper, bit_helper
    )

    total_tasks = len(nop_futures) + len(bit_futures)

    with (
        alive_bar(total_tasks, title="Processing data") as bar,
        ThreadPoolExecutor(max_workers=max_workers),
    ):
        process_futures(
            nop_futures,
            extract_nop_exp,
            lambda res: os.remove(res[0][0]),
            nop_instructions,
            segfaults,
            bar,
        )
        process_futures(
            bit_futures,
            extract_bit_exp,
            lambda res: [os.remove(b[0]) for b in res[0]],
            bit_instructions,
            segfaults,
            bar,
        )

    return nop_instructions, bit_instructions, segfaults


# put all of our simulations on the thread pool for execution
def submit_tasks(
    disasm, target, run_parameters, run_nop, run_bit, nop_helper, bit_helper
):
    nop_futures = []
    bit_futures = []

    with ThreadPoolExecutor() as executor:
        for inst_count, inst in enumerate(disasm, start=1):
            if run_bit:
                bit_futures.append(
                    executor.submit(
                        bit_helper, run_parameters, inst, target, inst_count
                    )
                )
            if run_nop:
                nop_futures.append(
                    executor.submit(
                        nop_helper, run_parameters, inst, target, inst_count
                    )
                )

    return nop_futures, bit_futures


# extract return values to push onto instruction set
def process_futures(futures, extractor_fn, cleanup_fn, instructions, segfaults, bar):
    for future in as_completed(futures):
        try:
            result = future.result()
            ERROR_FLAGS = ErrorStatus.RETURN_CODE | ErrorStatus.STDOUT
            if extractor_fn(result[0]) & ERROR_FLAGS:
                instructions.add((result[1], result[2]))
            if extractor_fn(result[0]) != ErrorStatus.SIGSEGV:
                segfaults.append(result[2])
            cleanup_fn(result)
        except Exception as e:
            print(f"Error processing future: {e}")
        bar()
