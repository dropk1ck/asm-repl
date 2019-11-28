from ansicolor import red 
from keystone import *
from keystone.keystone import KsError
from unicorn import *
from unicorn.x86_const import *

reg_map = {
    'rax': UC_X86_REG_RAX,
    'rbx': UC_X86_REG_RBX,
    'rcx': UC_X86_REG_RCX,
    'rdx': UC_X86_REG_RDX,
    'rsi': UC_X86_REG_RSI,
    'rdi': UC_X86_REG_RDI,
    'r8': UC_X86_REG_R8,
    'r9': UC_X86_REG_R9,
    'r10': UC_X86_REG_R10,
    'r11': UC_X86_REG_R11,
    'r12': UC_X86_REG_R12,
    'r13': UC_X86_REG_R13,
    'rsp': UC_X86_REG_RSP,
    'rbp': UC_X86_REG_RBP,
    'rip': UC_X86_REG_RIP,
}

class X64(object):
    def __init__(self, txt_addr, txt_size, stack_addr, stack_size):
        self.wordsize = 8
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

        self.asm = Ks(KS_ARCH_X86, KS_MODE_64)
        self.emu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.emu.mem_map(txt_addr, txt_size)
        self.emu.mem_map(stack_addr, stack_size)
        self.emu.mem_write(stack_addr, b'\x00'*stack_size)
        self.emu.reg_write(UC_X86_REG_RIP, txt_addr)
        self.emu.reg_write(UC_X86_REG_RSP, stack_addr)

        # sp and ip have changed
        self.reg_state['rip'] = txt_addr
        self.reg_state['rsp'] = stack_addr

    def print_state(self):
        regs = { }
        for r in reg_map:
            regs[r] = None

        for r in regs:
            regs[r] = self.emu.reg_read(reg_map[r])
            if self.reg_state[r] != regs[r]:
                regs[r] = red('{}:0x{:016x}'.format(r, regs[r]), bold=True)
            else:
                regs[r] = '{}:0x{:016x}'.format(r, regs[r])

        # eflags
        efl = self.emu.reg_read(UC_X86_REG_EFLAGS)
        flags = []
        for flag in self.flags:
            if efl & (1<<flag):
                flags.append(self.flags[flag])
        r_efl = 'eflags: ' + red(' '.join(flags))


        print("{0}  {1}  {2}  {3}".format(regs['rax'], regs['rbx'], regs['rcx'], regs['rdx']))
        print("{0}  {1}  {2}   {3}".format(regs['rsi'], regs['rdi'], regs['r8'], regs['r9']))
        print("{0}  {1}  {2}  {3}".format(regs['r10'], regs['r11'], regs['r12'], regs['r13']))
        print("{0}  {1}".format(regs['rsp'], regs['rbp']))
        print("{0}  {1}".format(regs['rip'], r_efl))
        return

    def get_ip(self):
        return self.emu.reg_read(UC_X86_REG_RIP)

    def get_sp(self):
        return self.emu.reg_read(UC_X86_REG_RSP)

    def get_stack_element(self, addr):
        return self.emu.mem_read(addr, 8)
