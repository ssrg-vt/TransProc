"""
DWARF register mappings
"""

AARCH64_NUM_REGS = 128

# General purpose aarch64 registers.
X0 = 0
X1 = 1
X2 = 2
X3 = 3
X4 = 4
X5 = 5
X6 = 6
X7 = 7
X8 = 8
X9 = 9
X10 = 10
X11 = 11
X12 = 12
X13 = 13
X14 = 14
X15 = 15
X16 = 16
X17 = 17
X18 = 18
X19 = 19
X20 = 20
X21 = 21
X22 = 22
X23 = 23
X24 = 24
X25 = 25
X26 = 26
X27 = 27
X28 = 28
X29 = 29
X30 = 30
SP = 31

#Floating-point unit (FPU)/SIMD registers
V0 = 64
V1 = 65
V2 = 66
V3 = 67
V4 = 68
V5 = 69
V6 = 70
V7 = 71
V8 = 72
V9 = 73
V10 = 74
V11 = 75
V12 = 76
V13 = 77
V14 = 78
V15 = 79
V16 = 80
V17 = 81
V18 = 82
V19 = 83
V20 = 84
V21 = 85
V22 = 86
V23 = 87
V24 = 88
V25 = 89
V26 = 90
V27 = 91
V28 = 92
V29 = 93
V30 = 94
V31 = 95

class RegsetAarch64:
    def __init__(self, core=None):
        if core:
            self._init(core)
        else:
            self._init_none()

    def _init(self, core):
        assert core['mtype'] == 'AARCH64', "The process image is not for aarch64"
        self.sp = core['ti_aarch64']['gpregs']['sp']
        self.pc = core['ti_aarch64']['gpregs']['pc']
        self.x = []
        for i in range(31):
            self.x.append(core['ti_aarch64']['gpregs']['regs'][i])
        self.v = []
        for i in range(64):
            self.v.append(core['ti_aarch64']['fpsimd']['vregs'][i])

    def _init_none(self):
        self.sp = 0
        self.pc = 0
        self.x = [0] * 31
        self.v = [0] * 64
    
    def copy_out(self, core):
        assert core['mtype'] == 'AARCH64', "The process image is not for aarch64"
        core['ti_aarch64']['gpregs']['sp'] = self.sp
        core['ti_aarch64']['gpregs']['pc'] = self.pc
        for i in range(31):
            core['ti_aarch64']['gpregs']['regs'][i] = self.x[i]
        for i in range(64):
            core['ti_aarch64']['fpsimd']['vregs'][i] = self.v[i]