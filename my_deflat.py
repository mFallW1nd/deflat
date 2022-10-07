from re import VERBOSE
from emu_utils import *
from emu_analysis import *
from unicorn import *
from unicorn.x86_const import *

def log_hook(emu, addr, size, user_data):
    # init
    disasm = get_disasm(emu, addr, size)

    # log
    if DEBUG and VERBOSE:
        print(hex(addr) + '\t' + disasm['op'] + '\t' + disasm['opstr'])


def step_over_hook(emu, addr, size, relevant):
    # init
    disasm = get_disasm(emu, addr, size)

    # step over
    if (disasm['op'] == 'call'):
        emu.reg_write(UC_X86_REG_RIP, addr+size)

    if (disasm['op'] == 'ret' or
        disasm['op'] == 'retn'
    ):
        print('\t\tretn node')
        emu.emu_stop()


def normal_hook(emu, addr, size, relevant):
    # init
    disasm = get_disasm(emu, addr, size)
    relevant.node_inst.append(disasm)

    # judge if have branch
    if ('cmov' in disasm['op']):
        # get information
        relevant.have_branch = True
        relevant.branch_type = disasm['op'][4:]
        relevant.cmov_inst = disasm

        # normal reg
        print("\t\tbranch 0 executing!")
        relevant.node_inst.clear()
        relevant.cmov_inst['branch'] = 0
        emulate_execution(
            filename,
            relevant.sg_node.addr,
            0xFFFFFFFF,
            branch_hook,
            relevant
        )

        # condition_reg
        print("\t\tbranch 1 executing!")
        relevant.node_inst.clear()
        relevant.cmov_inst['branch'] = 1
        emulate_execution(
            filename,
            relevant.sg_node.addr,
            0xFFFFFFFF,
            branch_hook,
            relevant
        )

        # stop
        emu.emu_stop()

    # add coedge
    if (hex(addr) in tar_func.relevant_nodes and
            addr != relevant.sg_node.addr
        ):
        print('\t\tbranch', 'is:' + hex(addr))
        relevant.branch_addr[0] = addr
        emu.emu_stop()


def branch_hook(emu, addr, size, relevant):
    # init
    disasm = get_disasm(emu, addr, size)
    relevant.node_inst.append(disasm)

    # change state value
    if ('cmov' in disasm['op']):
        reg0 = get_reg_in_str(relevant.cmov_inst['opstr'].split(', ')[0])
        reg1 = get_reg_in_str(relevant.cmov_inst['opstr'].split(', ')[1])

        if (relevant.cmov_inst['branch'] == 1):
            reg1_value = emu.reg_read(reg1[1])
            emu.reg_write(reg0[1], reg1_value)

        emu.reg_write(UC_X86_REG_RIP, addr+size)

    # add coedge
    if (hex(addr) in tar_func.relevant_nodes and
            len(relevant.node_inst) > 1
        ):
        print('\t\t\tbranch', relevant.cmov_inst['branch'], 'is:' + hex(addr))

        if relevant.cmov_inst['branch'] == 0:
            relevant.branch_addr[0] = addr
        elif relevant.cmov_inst['branch'] == 1:
            relevant.branch_addr[1] = addr

        emu.emu_stop()


def emulate_execution(filename, start_addr, end_addr, hook_func, user_data):
    emu = Uc(UC_ARCH_X86, UC_MODE_64)

    textSec = get_section(filename, '.text')

    textSec_entry = textSec.header['sh_addr']
    textSec_size = textSec.header['sh_size']
    textSec_raw = textSec.header['sh_offset']

    TEXT_BASE  = textSec_entry >> 12 << 12
    TEXT_SIZE  = (textSec_size + 0x1000) >> 12 << 12
    TEXT_RBASE = textSec_raw >> 12 << 12

    VOID_BASE  = 0x00000000
    VOID_SIZE  = TEXT_BASE

    STACK_BASE = TEXT_BASE + TEXT_SIZE
    STACK_SIZE = 0xFFFFFFFF - STACK_BASE >> 12 << 12

    emu.mem_map(TEXT_BASE, TEXT_SIZE)
    emu.mem_map(VOID_BASE, VOID_SIZE)
    emu.mem_map(STACK_BASE, STACK_SIZE)

    emu.mem_write(TEXT_BASE, read(filename)[TEXT_RBASE:TEXT_RBASE+TEXT_SIZE])
    emu.reg_write(UC_X86_REG_RBP, STACK_BASE + 0x1000)
    emu.reg_write(UC_X86_REG_RSP, STACK_BASE + STACK_SIZE // 2)

    emu.hook_add(UC_HOOK_CODE, log_hook)
    emu.hook_add(UC_HOOK_CODE, step_over_hook, user_data)
    emu.hook_add(UC_HOOK_CODE, hook_func, user_data)

    emu.emu_start(start_addr, end_addr)


if __name__ == '__main__':
    DEBUG   = True
    VERBOSE = False
    if DEBUG:
        filename   = './ezam'
        start_addr = 0x4008F0
        end_addr   = 0x401B49
    else:
        filename, start_addr, end_addr = get_args()

    # do some initialize
    print('\n[+] < Preparing for emulate execution >')
    tar_func = TarFunc(filename, start_addr, end_addr)

    # reconstruct control flow
    print('\n[+] < Reconstructing control flow >')
    for relevant in tar_func.relevant_nodes:
        print('['+relevant+'] ', end='')
        print("relevant executing!")
        emulate_execution(
            filename,
            int(relevant, 16),
            0xFFFFFFFF,
            normal_hook,
            tar_func.relevant_nodes[relevant]
        )

    # patch binary
    print('\n[+] < Patching binary file >')
    new_filename = tar_func.filename + '_recovered_' + hex(start_addr)

    for relevant in tar_func.relevant_nodes.values():
        relevant.get_node_inst(tar_func)
        if relevant.sg_node.addr != tar_func.retn_node.addr:
            relevant.patch(tar_func)
    tar_func.fill_nop()

    with open(new_filename, 'wb') as f:
        f.write(tar_func.file_buf)

    # success
    print('\n[*] Recovered successfully! The output file is:', new_filename)
