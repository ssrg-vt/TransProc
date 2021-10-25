from . import reg_x86_64
from . import reg_aarch64

_x86_64_ra_offset = 0x8
_x86_64_cfa_offset_funcentry = 0x8
_x86_64_stack_alignment = 0x10

_callee_saved_x86_64 = [
    reg_x86_64.RBX,
    reg_x86_64.RBP,
    reg_x86_64.R12,
    reg_x86_64.R13,
    reg_x86_64.R14,
    reg_x86_64.R15,
    reg_x86_64.RIP
]

_num_callee_saved_x86_64 = len(_callee_saved_x86_64)

_callee_saved_size_x86_64 = [8] * _num_callee_saved_x86_64


def _is_callee_saved_x86_64(regnum):
    if(regnum in _callee_saved_size_x86_64):
        return True
    else:
        return False


def _callee_reg_size_x86_64(regnum):
    if(_is_callee_saved_x86_64(regnum)):
        return 8
    else:
        raise Exception(
            "Callee saved register for x86-64 cannot be %d" % regnum)


x86 = {
    'num_callee_saved': _num_callee_saved_x86_64,
    'callee_saved': _callee_saved_x86_64,
    'callee_saved_size': _callee_saved_size_x86_64,
    'ra_offset': _x86_64_ra_offset,
    'cfa_offset_funcentry': _x86_64_cfa_offset_funcentry,
    'is_callee_saved': _is_callee_saved_x86_64,
    'callee_reg_size': _callee_reg_size_x86_64
}

_aarch64_stack_alignment = 0x10
_aarch64_ra_offset = 0x8
_aarch64_cfa_offset_funcentry = 0x0

_callee_saved_aarch64 = [
    reg_aarch64.X19,
    reg_aarch64.X20,
    reg_aarch64.X21,
    reg_aarch64.X22,
    reg_aarch64.X23,
    reg_aarch64.X24,
    reg_aarch64.X25,
    reg_aarch64.X26,
    reg_aarch64.X27,
    reg_aarch64.X28,
    reg_aarch64.X29,
    reg_aarch64.X30,
    reg_aarch64.V8,
    reg_aarch64.V9,
    reg_aarch64.V10,
    reg_aarch64.V11,
    reg_aarch64.V12,
    reg_aarch64.V13,
    reg_aarch64.V14,
    reg_aarch64.V15
]

_num_callee_saved_aarch64 = len(_callee_saved_aarch64)

_callee_saved_size_aarch64 = [8] * _num_callee_saved_aarch64


def _is_callee_saved_aarch64(regnum):
    if regnum in _callee_saved_aarch64:
        return True
    else:
        return False


def _callee_reg_size_aarch64(regnum):
    if _is_callee_saved_aarch64(regnum):
        return 8
    else:
        raise Exception(
            "Callee saved register for aarch64 cannot be %d" % regnum)


aarch = {
    'num_callee_saved': _num_callee_saved_aarch64,
    'callee_saved': _callee_saved_aarch64,
    'callee_saved_size': _callee_saved_size_aarch64,
    'ra_offset': _aarch64_ra_offset,
    'cfa_offset_funcentry': _aarch64_cfa_offset_funcentry,
    'is_callee_saved': _is_callee_saved_aarch64,
    'callee_reg_size': _callee_reg_size_aarch64
}
