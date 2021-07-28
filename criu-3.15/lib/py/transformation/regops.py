
def _x86_sp(regset):
    return regset.rsp

def _x86_bp(regset):
    return regset.rbp

def _x86_pc(regset):
    return regset.rip

def _aarch_sp(regset):
    return regset.sp

def _aarch_pc(regset):
    return regset.pc

def _aarch_bp(regset):
    return regset.x[29]


x86 = {
    'sp' : _x86_sp,
    'bp' : _x86_bp,
    'pc' : _x86_pc
}

aarch = {
    'sp' : _aarch_sp,
    'bp' : _aarch_bp,
    'pc' : _aarch_pc
}