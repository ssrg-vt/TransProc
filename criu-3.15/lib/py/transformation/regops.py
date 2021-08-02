
def _x86_sp(regset):
    return regset.rsp

def _x86_bp(regset):
    return regset.rbp

def _x86_pc(regset):
    return regset.rip

def _x86_set_sp(sp, regset):
    regset.rsp = sp

def _x86_set_bp(bp, regset):
    regset.rsp = bp

def _x86_set_pc(pc, regset):
    regset.rip = pc

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


x86 = {
    'sp' : _x86_sp,
    'bp' : _x86_bp,
    'pc' : _x86_pc,
    'set_sp' : _x86_set_sp,
    'set_bp' : _x86_set_bp,
    'set_pc' : _x86_set_pc
}

aarch = {
    'sp' : _aarch_sp,
    'bp' : _aarch_bp,
    'pc' : _aarch_pc,
    'set_sp' : _aarch_set_sp,
    'set_bp' : _aarch_set_bp,
    'set_pc' : _aarch_set_pc
}