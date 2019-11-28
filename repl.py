#!/usr/bin/env python3

import argparse
from collections import namedtuple
from keystone import *
from keystone.keystone import KsError
from prompt_toolkit import prompt
from prompt_toolkit.history import InMemoryHistory
from pygments.lexers.asm import NasmLexer
from unicorn import *
from unicorn.x86_const import *
from x86 import X86
from x64 import X64

archs = ['x86', 'x64', 'arm', 'thumb', 'mips']
Arch = namedtuple('Arch', 'ks_arch ks_mode uc_arch uc_mode')
arch_dict = {
    'x86': Arch(KS_ARCH_X86, KS_MODE_32, UC_ARCH_X86, UC_MODE_32),
    'x64': Arch(KS_ARCH_X86, KS_MODE_64, UC_ARCH_X86, UC_MODE_64),
    'arm': Arch(KS_ARCH_ARM, KS_MODE_ARM, UC_ARCH_ARM, UC_MODE_ARM),
    'thumb': Arch(KS_ARCH_ARM, KS_MODE_THUMB, UC_ARCH_ARM, UC_MODE_THUMB),
    'mips': Arch(KS_ARCH_MIPS, KS_MODE_MIPS32, UC_ARCH_MIPS, UC_MODE_MIPS32),
}
txt_addr = 0x1000
txt_size = 0x1000 
starting_stack_addr = 0x2000
starting_stack_size = 0x1000

def nop(mu):
    pass

def repl_help():
    pass

def main(arch_name):
    if arch_name not in archs:
        print('Bad arch passed to main!')
        return
    
    # initialize machine
    if arch_name == 'x86':
        m = X86(txt_addr, txt_size, starting_stack_addr, starting_stack_size)
    elif arch_name == 'x64':
        m = X64(txt_addr, txt_size, starting_stack_addr, starting_stack_size)

    history = InMemoryHistory()
    while True:
        txt = prompt('> ', history=history)
        if txt == '':
            continue
        if txt == 'quit':
            return
        if txt == '?':
            repl_help()
            continue
        if txt == '.regs':
            m.print_state()
            continue
        if txt == '.reset':
            m = X86(txt_addr, txt_size, stack_addr, stack_size)
            m.print_state()
            continue
        if txt == '.stack':
            padding = m.wordsize*2+2
            print('Stack:')
            for x in range(0, 8):
                stack_addr = m.get_sp() + (m.wordsize*x)
                try:
                    stack_contents = int.from_bytes(m.get_stack_element(stack_addr), m.endianness)
                    print(f'  {stack_addr:#0{padding}x}: {stack_contents:#0{padding}x}')
                except UcError as uce:
                    print('Invalid memory region')
                    break
            continue
        try:
            encoding, count = m.asm.asm(txt)
            if encoding is None:
                print('Assembler error, check your syntax')
                continue
            code = bytes(encoding) 
            ip = m.get_ip()
            m.emu.mem_write(ip, code)
            m.emu.emu_start(ip, ip + len(code))
            m.print_state()
        except KsError as kse:
            print('Assembler error: {}'.format(kse))
            continue
        except UcError as uce:
            print('Emulator error: {}'.format(uce))
            continue

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='a python-based ASM repl')
    parser.add_argument('--arch', default='x86', help='specify architecture (default x86)',
            choices=archs)

    args = parser.parse_args()
    main(args.arch)
