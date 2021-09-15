"""
DWARF register mappings
"""

X86_64_NUM_REGS = 67

# General purpose x86-64 registers
RAX = 0
RDX = 1
RCX = 2
RBX = 3
RSI = 4
RDI = 5
RBP = 6
RSP = 7
R8 = 8
R9 = 9
R10 = 10
R11 = 11
R12 = 12
R13 = 13
R14 = 14
R15 = 15
RIP = 16

# Streaming SIMD Extension (SSE) registers
XMM0 = 17
XMM1 = 18
XMM2 = 19
XMM3 = 20
XMM4 = 21
XMM5 = 22
XMM6 = 23
XMM7 = 24
XMM8 = 25
XMM9 = 26
XMM10 = 27
XMM11 = 28
XMM12 = 29
XMM13 = 30
XMM14 = 31
XMM15 = 32

class RegsetX8664:
    def __init__(self, core = None):
        if core:
            self._init(core)
        else:
            self._init_none()        

    def _init(self, core):
        assert core['mtype'] == 'X86_64', "The process image is not for x86_64"
        self.rip = core['thread_info']['gpregs']['ip']
        self.rax = core['thread_info']['gpregs']['ax']
        self.rdx = core['thread_info']['gpregs']['dx']
        self.rcx = core['thread_info']['gpregs']['cx']
        self.rbx = core['thread_info']['gpregs']['bx']
        self.rsi = core['thread_info']['gpregs']['si']
        self.rdi = core['thread_info']['gpregs']['di']
        self.rbp = core['thread_info']['gpregs']['bp']
        self.rsp = core['thread_info']['gpregs']['sp']
        self.r8 = core['thread_info']['gpregs']['r8']
        self.r9 = core['thread_info']['gpregs']['r9']
        self.r10 = core['thread_info']['gpregs']['r10']
        self.r11 = core['thread_info']['gpregs']['r11']
        self.r12 = core['thread_info']['gpregs']['r12']
        self.r13 = core['thread_info']['gpregs']['r13']
        self.r14 = core['thread_info']['gpregs']['r14']
        self.r15 = core['thread_info']['gpregs']['r15']
        self.cs = core['thread_info']['gpregs']['cs']
        self.ss = core['thread_info']['gpregs']['ss']
        self.ds = core['thread_info']['gpregs']['ds']
        self.es = core['thread_info']['gpregs']['es']
        self.fs = core['thread_info']['gpregs']['fs']
        self.gs = core['thread_info']['gpregs']['gs']
        self.rflags = core['thread_info']['gpregs']['flags']
        self.mmx = [0] * 8 #TODO Read from file
        self.xmm = []
        for i in range(62): # core image has 62 entries for xmm
            self.xmm.append(core['thread_info']['fpregs']['xmm_space'][i])
        self.st = []
        for i in range(32): # core image has 32 entries for st
            self.st.append(core['thread_info']['fpregs']['st_space'][i])

    def _init_none(self):
        self.rip = 0
        self.rax = 0
        self.rdx = 0
        self.rcx = 0
        self.rbx = 0
        self.rsi = 0
        self.rdi = 0
        self.rbp = 0
        self.rsp = 0
        self.r8 = 0
        self.r9 = 0
        self.r10 = 0
        self.r11 = 0
        self.r12 = 0
        self.r13 = 0
        self.r14 = 0
        self.r15 = 0
        self.cs = 0
        self.ss = 0
        self.ds = 0
        self.es = 0
        self.fs = 0
        self.gs = 0
        self.rflags = 0
        self.mmx = [0] * 8 #TODO Read from file
        self.xmm = [0] * 62
        self.st = [0] * 32
    
    def copy_out(self, core):
        assert core['mtype'] == 'X86_64', "The process image is not for x86_64"
        core['thread_info']['gpregs']['ip'] = self.rip
        core['thread_info']['gpregs']['ax'] = self.rax
        core['thread_info']['gpregs']['dx'] = self.rdx
        core['thread_info']['gpregs']['cx'] = self.rcx
        core['thread_info']['gpregs']['bx'] = self.rbx
        core['thread_info']['gpregs']['si'] = self.rsi
        core['thread_info']['gpregs']['di'] = self.rdi
        core['thread_info']['gpregs']['bp'] = self.rbp
        core['thread_info']['gpregs']['sp'] = self.rsp
        core['thread_info']['gpregs']['r8'] = self.r8
        core['thread_info']['gpregs']['r9'] = self.r9
        core['thread_info']['gpregs']['r10'] = self.r10
        core['thread_info']['gpregs']['r11'] = self.r11
        core['thread_info']['gpregs']['r12'] = self.r12
        core['thread_info']['gpregs']['r13'] = self.r13
        core['thread_info']['gpregs']['r14'] = self.r14
        core['thread_info']['gpregs']['r15'] = self.r15
        core['thread_info']['gpregs']['cs'] = self.cs
        core['thread_info']['gpregs']['ss'] = self.ss
        core['thread_info']['gpregs']['ds'] = self.ds
        core['thread_info']['gpregs']['es'] = self.es
        core['thread_info']['gpregs']['fs'] = self.fs
        core['thread_info']['gpregs']['gs'] = self.gs
        core['thread_info']['gpregs']['flags'] = self.rflags
        # self.mmx = [0] * 8 #TODO Read from file
        for i in range(62): # core image has 62 entries for xmm
            core['thread_info']['fpregs']['xmm_space'][i] = self.xmm[i]
        for i in range(32): # core image has 32 entries for st
            core['thread_info']['fpregs']['st_space'][i] = self.st