from keystone import *
from keystone.keystone import KsError
from unicorn import *
from unicorn.x86_const import *

class X86(object):
    def __init__(self, start_addr):
        self.asm = Ks(KS_ARCH_X86, KS_MODE_32)
        self.emu = Uc(UC_ARCH_X86, UC_MODE_32)
        self.emu.reg_write(UC_X86_REG_EIP, start_addr)

    def print_state(self):
        r_eax = self.emu.reg_read(UC_X86_REG_EAX)
        r_ebx = self.emu.reg_read(UC_X86_REG_EBX)
        r_ecx = self.emu.reg_read(UC_X86_REG_ECX)
        r_edx = self.emu.reg_read(UC_X86_REG_EDX)
        r_esi = self.emu.reg_read(UC_X86_REG_ESI)
        r_edi = self.emu.reg_read(UC_X86_REG_EDI)
        r_esp = self.emu.reg_read(UC_X86_REG_ESP)
        r_ebp = self.emu.reg_read(UC_X86_REG_EBP)
        r_eip = self.emu.reg_read(UC_X86_REG_EIP)

        print("eax:0x{:08x}  ebx: 0x{:08x}  ecx: 0x{:08x}  edx: 0x{:08x}".format(r_eax, r_ebx, r_ecx, r_edx))
        print("esi:0x{:08x}  edi: 0x{:08x}  esp: 0x{:08x}  ebp: 0x{:08x}".format(r_esi, r_edi, r_esp, r_ebp))
        print("eip:0x{:08x}  eflags: ????".format(r_eip))
        return

    def get_ip(self):
        return self.emu.reg_read(UC_X86_REG_EIP)
