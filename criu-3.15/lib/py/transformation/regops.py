from . import reg_x86_64
from . import reg_aarch64


def _x86_sp(regset):
    return regset.rsp

def _x86_bp(regset):
    return regset.rbp

def _x86_pc(regset):
    return regset.rip

def _x86_set_sp(sp, regset):
    regset.rsp = sp

def _x86_set_bp(bp, regset):
    regset.rbp = bp

def _x86_set_pc(pc, regset):
    regset.rip = pc

def _x86_get_reg_val(regnum, regset):
    if regnum == reg_x86_64.RAX:
        return regset.rax
    elif regnum == reg_x86_64.RBX:
        return regset.rbx
    elif regnum == reg_x86_64.RCX:
        return regset.rcx
    elif regnum == reg_x86_64.RDX:
        return regset.rdx
    elif regnum == reg_x86_64.RSI:
        return regset.rsi
    elif regnum == reg_x86_64.RDI:
        return regset.rdi
    elif regnum == reg_x86_64.RSP:
        return regset.rsp
    elif regnum == reg_x86_64.RBP:
        return regset.rbp
    elif regnum == reg_x86_64.R8:
        return regset.r8
    elif regnum == reg_x86_64.R9:
        return regset.r9
    elif regnum == reg_x86_64.R10:
        return regset.r10
    elif regnum == reg_x86_64.R11:
        return regset.r11
    elif regnum == reg_x86_64.R12:
        return regset.r12
    elif regnum == reg_x86_64.R13:
        return regset.r13
    elif regnum == reg_x86_64.R14:
        return regset.r14
    elif regnum == reg_x86_64.R15:
        return regset.r15
    elif regnum == reg_x86_64.RIP:
        return regset.rip
    elif regnum == reg_x86_64.XMM0:
        return regset.xmm[0]
    elif regnum == reg_x86_64.XMM1:
        return regset.xmm[1]
    elif regnum == reg_x86_64.XMM2:
        return regset.xmm[2]
    elif regnum == reg_x86_64.XMM3:
        return regset.xmm[3]
    elif regnum == reg_x86_64.XMM4:
        return regset.xmm[4]
    elif regnum == reg_x86_64.XMM5:
        return regset.xmm[5]
    elif regnum == reg_x86_64.XMM6:
        return regset.xmm[6]
    elif regnum == reg_x86_64.XMM7:
        return regset.xmm[7]
    elif regnum == reg_x86_64.XMM8:
        return regset.xmm[8]
    elif regnum == reg_x86_64.XMM9:
        return regset.xmm[9]
    elif regnum == reg_x86_64.XMM10:
        return regset.xmm[10]
    elif regnum == reg_x86_64.XMM11:
        return regset.xmm[11]
    elif regnum == reg_x86_64.XMM12:
        return regset.xmm[12]
    elif regnum == reg_x86_64.XMM13:
        return regset.xmm[13]
    elif regnum == reg_x86_64.XMM14:
        return regset.xmm[14]
    elif regnum == reg_x86_64.XMM15:
        return regset.xmm[15]
    else:
        raise Exception("Register not yet supported!")

def _x86_set_reg_val(regnum, val, regset):
    if regnum == reg_x86_64.RAX:
        regset.rax = val
    elif regnum == reg_x86_64.RBX:
        regset.rbx = val
    elif regnum == reg_x86_64.RCX:
        regset.rcx = val
    elif regnum == reg_x86_64.RDX:
        regset.rdx = val
    elif regnum == reg_x86_64.RSI:
        regset.rsi = val
    elif regnum == reg_x86_64.RDI:
        regset.rdi = val
    elif regnum == reg_x86_64.RSP:
        regset.rsp = val
    elif regnum == reg_x86_64.RBP:
        regset.rbp = val
    elif regnum == reg_x86_64.R8:
        regset.r8 = val
    elif regnum == reg_x86_64.R9:
        regset.r9 = val
    elif regnum == reg_x86_64.R10:
        regset.r10 = val
    elif regnum == reg_x86_64.R11:
        regset.r11 = val
    elif regnum == reg_x86_64.R12:
        regset.r12 = val
    elif regnum == reg_x86_64.R13:
        regset.r13 = val
    elif regnum == reg_x86_64.R14:
        regset.r14 = val
    elif regnum == reg_x86_64.R15:
        regset.r15 = val
    elif regnum == reg_x86_64.RIP:
        regset.rip = val
    elif regnum == reg_x86_64.XMM0:
        regset.xmm[0] = val
    elif regnum == reg_x86_64.XMM1:
        regset.xmm[1] = val
    elif regnum == reg_x86_64.XMM2:
        regset.xmm[2] = val
    elif regnum == reg_x86_64.XMM3:
        regset.xmm[3] = val
    elif regnum == reg_x86_64.XMM4:
        regset.xmm[4] = val
    elif regnum == reg_x86_64.XMM5:
        regset.xmm[5] = val
    elif regnum == reg_x86_64.XMM6:
        regset.xmm[6] = val
    elif regnum == reg_x86_64.XMM7:
        regset.xmm[7] = val
    elif regnum == reg_x86_64.XMM8:
        regset.xmm[8] = val
    elif regnum == reg_x86_64.XMM9:
        regset.xmm[9] = val
    elif regnum == reg_x86_64.XMM10:
        regset.xmm[10] = val
    elif regnum == reg_x86_64.XMM11:
        regset.xmm[11] = val
    elif regnum == reg_x86_64.XMM12:
        regset.xmm[12] = val
    elif regnum == reg_x86_64.XMM13:
        regset.xmm[13] = val
    elif regnum == reg_x86_64.XMM14:
        regset.xmm[14] = val
    elif regnum == reg_x86_64.XMM15:
        regset.xmm[15] = val
    else:
        raise Exception("Register not yet supported!")

def _x86_bp_regnum():
    return reg_x86_64.RBP

def _aarch_sp(regset):
    return regset.sp

def _aarch_pc(regset):
    return regset.pc

def _aarch_bp(regset):
    return regset.x[29]

def _aarch_set_sp(sp, regset):
    regset.sp = sp

def _aarch_set_pc(pc, regset):
    regset.pc = pc

def _aarch_set_bp(bp, regset):
    regset.x[29] = bp

def _aarch64_get_reg_val(regnum, regset):
    if regnum <= 30:
        return regset.x[regnum]
    elif regnum == reg_aarch64.SP:
        return regset.sp
    elif regnum <= 95 and regnum >= 64:
        return regset.v[regnum - 64]
    else:
        raise Exception("Register not yet supported")

def _aarch64_set_reg_val(regnum, val, regset):
    if regnum <= 30:
        regset.x[regnum] = val
    elif regnum == reg_aarch64.SP:
        regset.sp = val
    elif regnum <= 95 and regnum >= 64:
        regset.v[regnum - 64] = val
    else:
        raise Exception("Register not yet supported")

def _aarch64_bp_regnum():
    return reg_aarch64.X29

x86 = {
    'sp' : _x86_sp,
    'bp' : _x86_bp,
    'pc' : _x86_pc,
    'set_sp' : _x86_set_sp,
    'set_bp' : _x86_set_bp,
    'set_pc' : _x86_set_pc,
    'reg_val' : _x86_get_reg_val,
    'set_reg' : _x86_set_reg_val,
    'bp_regnum' : _x86_bp_regnum
}

aarch = {
    'sp' : _aarch_sp,
    'bp' : _aarch_bp,
    'pc' : _aarch_pc,
    'set_sp' : _aarch_set_sp,
    'set_bp' : _aarch_set_bp,
    'set_pc' : _aarch_set_pc,
    'reg_val' : _aarch64_get_reg_val,
    'set_reg' : _aarch64_set_reg_val,
    'bp_regnum' : _aarch64_bp_regnum
}