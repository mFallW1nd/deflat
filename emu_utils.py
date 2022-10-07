from elftools.elf.elffile import *
from unicorn.x86_const import*
from capstone import *
from keystone import *
from struct import *
import argparse
import sys

def read(name):
    with open(name, 'rb') as f:
        return f.read()

def get_reg_in_str(str):
    REG = [0] * 2

    if   'bp' in str:
        REG[0] = 'rbp'
        REG[1] = UC_X86_REG_RBP

    if   'ax' in str:
        REG[0] = 'rax'
        REG[1] = UC_X86_REG_RAX

    elif 'bx' in str:
        REG[0] = 'rbx'
        REG[1] = UC_X86_REG_RBX

    elif 'cx' in str:
        REG[0] = 'rcx'
        REG[1] = UC_X86_REG_RCX

    elif 'dx' in str:
        REG[0] = 'rdx'
        REG[1] = UC_X86_REG_RDX

    elif 'di' in str:
        REG[0] = 'rdi'
        REG[1] = UC_X86_REG_RDI

    elif 'si' in str:
        REG[0] = 'rsi'
        REG[1] = UC_X86_REG_RSI

    elif 'r8' in str:
        REG[0] = 'r8'
        REG[1] = UC_X86_REG_R8

    elif 'r9' in str:
        REG[0] = 'r9'
        REG[1] = UC_X86_REG_R9    

    elif 'r10' in str:
        REG[0] = 'r10'
        REG[1] = UC_X86_REG_R10

    elif 'r11' in str:
        REG[0] = 'r11'
        REG[1] = UC_X86_REG_R11

    elif 'r12' in str:
        REG[0] = 'r12'
        REG[1] = UC_X86_REG_R12   
    
    elif 'r13' in str:
        REG[0] = 'r13'
        REG[1] = UC_X86_REG_R13

    elif 'r14' in str:
        REG[0] = 'r14'
        REG[1] = UC_X86_REG_R14

    elif 'r15' in str:
        REG[0] = 'r15'
        REG[1] = UC_X86_REG_R15     

    return REG

def get_asm(asm_str, addr):
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    asm = ks.asm(asm_str, addr, as_bytes=True)[0]

    return asm

def get_disasm(emu, addr, size):
    asm = emu.mem_read(addr, size)
    cs  = Cs(CS_ARCH_X86, CS_MODE_64)

    for i in cs.disasm(asm, addr):
        op      = i.mnemonic
        opstr   = i.op_str
        sz      = i.size
        address = i.address
        bytes   = i.bytes

        disasm = {
            'op':op, 
            'opstr':opstr, 
            'size':sz, 
            'addr':address, 
            'bytes':bytes
        }

        break

    return disasm

def get_section(file_name, section_name):
    with open(file_name, 'rb') as f:
        ELF = ELFFile(f)
        section = ELF.get_section_by_name(section_name)
    
    return section

def get_args():
    parser = argparse.ArgumentParser(description="deflat control flow script")

    parser.add_argument(
        "-f",
        "--file",
        help="binary to analyze"
    )

    parser.add_argument(
        "-a",
        "--addr",
        help="address of target function in hex format"
    )

    parser.add_argument(
        "-e",
        "--end",
        help="end address of target function in hex format"
    )
    
    args = parser.parse_args()

    if args.file is None or args.addr is None or args.end is None:
        parser.print_help()
        sys.exit(0)

    return args.file, int(args.addr, 16), int(args.end, 16)