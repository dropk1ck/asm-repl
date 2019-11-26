from ansicolor import red 
from keystone import *
from keystone.keystone import KsError
from unicorn import *
from unicorn.x86_const import *

reg_map = {
    'eax': UC_X86_REG_EAX,
    'ebx': UC_X86_REG_EBX,
    'ecx': UC_X86_REG_ECX,
    'edx': UC_X86_REG_EDX,
    'esi': UC_X86_REG_ESI,
    'edi': UC_X86_REG_EDI,
    'esp': UC_X86_REG_ESP,
    'ebp': UC_X86_REG_EBP,
    'eip': UC_X86_REG_EIP,
}

class X86(object):
    def __init__(self, txt_addr, txt_size, stack_addr, stack_size):
        self.wordsize = 4
        self.endianness = 'little'
        self.flags = {
            0: "CARRY",
            2: "PARITY",
            4: "ADJUST",
            6: "ZERO",
            7: "SIGN",
            8: "TRAP",
            9: "INTERRUPT",
            10: "DIRECTION",
            11: "OVERFLOW",
            16: "RESUME",
            17: "VIRTUALx86",
            21: "IDENTIFICATION",
        }

        # initialize saved register state
        self.reg_state = { }
        for r in reg_map:
            self.reg_state[r] = 0

        self.asm = Ks(KS_ARCH_X86, KS_MODE_32)
        self.emu = Uc(UC_ARCH_X86, UC_MODE_32)
        self.emu.mem_map(txt_addr, txt_size)
        self.emu.mem_map(stack_addr, stack_size)
        self.emu.mem_write(stack_addr, b'\x00'*stack_size)
        self.emu.reg_write(UC_X86_REG_EIP, txt_addr)
        self.emu.reg_write(UC_X86_REG_ESP, stack_addr)

    def print_state(self):
        regs = { }
        for r in reg_map:
            regs[r] = None

        for r in regs:
            regs[r] = self.emu.reg_read(reg_map[r])
            if self.reg_state[r] != regs[r]:
                regs[r] = red('{}:0x{:08x}'.format(r, regs[r]), bold=True)
            else:
                regs[r] = '{}:0x{:08x}'.format(r, regs[r])

        # eflags
        efl = self.emu.reg_read(UC_X86_REG_EFLAGS)
        flags = []
        for flag in self.flags:
            if efl & (1<<flag):
                flags.append(self.flags[flag])
        r_efl = 'eflags: ' + red(' '.join(flags))


        print("{0}  {1}  {2}  {3}".format(regs['eax'], regs['ebx'], regs['ecx'], regs['edx']))
        print("{0}  {1}  {2}  {3}".format(regs['esi'], regs['edi'], regs['esp'], regs['ebp']))
        print("{0}  {1}".format(regs['eip'], r_efl))
        return

    def get_ip(self):
        return self.emu.reg_read(UC_X86_REG_EIP)
    
    def get_sp(self):
        return self.emu.reg_read(UC_X86_REG_ESP)

    def get_stack_element(self, addr):
        return self.emu.mem_read(addr, 4)

