import struct

FUNC_RECORD_SIZE = 32
CONST_RECORD_SIZE = 8
LIVE_VALUE_SIZE = 12
ARCH_LIVE_VALUE_SIZE = 20
LIVE_OUT_RECORD_SIZE = 4


class FunctionRecord:
    def __init__(self, function_addr, stack_size, record_count, num_unwind, unwind_offset):
        self.function_addr = function_addr
        self.stack_size = stack_size
        self.record_count = record_count
        self.num_unwind = num_unwind
        self.unwind_offset = unwind_offset


class LiveOutRecord:
    def __init__(self, regnum, reserved, size):
        self.regnum = regnum
        self.reserved = reserved
        self.size = size


class LiveValue:
    def __init__(self, is_temp, is_duplicate, is_alloca, is_ptr, type, size, regnum, offset_or_const, alloca_size):
        self.is_temp = is_temp
        self.is_duplicate = is_duplicate
        self.is_alloca = is_alloca
        self.is_ptr = is_ptr
        self.type = type
        self.size = size
        self.regnum = regnum
        self.offset_or_const = offset_or_const
        self.alloca_size = alloca_size


class ArchLiveValue:
    def __init__(self, is_ptr, bit_pad, type, size, regnum, offset, operand_type, is_gen, inst_type, operand_size, operand_regnum, operand_offset_or_constant):
        self.is_ptr = is_ptr
        self.bit_pad = bit_pad
        self.type = type
        self.size = size
        self.regnum = regnum
        self.offset = offset
        self.operand_type = operand_type
        self.is_gen = is_gen
        self.inst_type = inst_type
        self.operand_size = operand_size
        self.operand_regnum = operand_regnum
        self.operand_offset_or_constant = operand_offset_or_constant


class CallSiteRecord:
    def __init__(self, id, func_idx, offset, reserved, num_locations, locations, padding, num_live_outs, live_outs, padding2, num_arch_live, arch_live):
        self.id = id
        self.func_idx = func_idx
        self.offset = offset
        self.reserved = reserved
        self.num_locations = num_locations
        self.location = locations
        self.padding = padding
        self.num_live_outs = num_live_outs
        self.live_outs = live_outs
        self.padding2 = padding2
        self.num_arch_live = num_arch_live
        self.arch_live = arch_live

    def size(self):
        return 32 + (self.num_locations * LIVE_VALUE_SIZE) + (self.num_live_outs * LIVE_OUT_RECORD_SIZE) + (self.num_arch_live * ARCH_LIVE_VALUE_SIZE)


class StackMap:
    def __init__(self, version, reserved, reserved2, num_functions, num_constants, num_records, function_records, constants, call_sites):
        self.version = version
        self.reserved = reserved
        self.reserved2 = reserved2
        self.num_functions = num_functions
        self.num_constants = num_constants
        self.num_records = num_records
        self.function_records = function_records
        self.constants = constants
        self.call_sites = call_sites


def parse_stack_maps(section):
    buffer = section.data()
    offset = 0
    stack_maps = []
    while offset < section.data_size:
        version = buffer[offset]
        reserved = buffer[offset+1]
        reserved2 = struct.unpack('<H', buffer[offset+2:offset+4])[0]
        num_funcs = struct.unpack('<I', buffer[offset+4:offset+8])[0]
        num_constants = struct.unpack('<I', buffer[offset+8:offset+12])[0]
        num_records = struct.unpack('<I', buffer[offset+12:offset+16])[0]
        func_records = parse_function_records(buffer, offset, num_funcs, 16)
        constants = parse_constants(
            buffer, offset, num_constants, 16+(num_funcs*FUNC_RECORD_SIZE))
        call_sites = parse_call_site_records(buffer, offset, num_records, 16+(
            num_funcs*FUNC_RECORD_SIZE)+(num_constants*CONST_RECORD_SIZE))
        stack_map = StackMap(version, reserved, reserved2, num_funcs,
                             num_constants, num_records, func_records, constants, call_sites)
        stack_maps.append(stack_map)
        offset += 16+(num_funcs*FUNC_RECORD_SIZE) + \
            (num_constants*CONST_RECORD_SIZE)
        for c in call_sites:
            offset += c.size()
    return stack_maps


def parse_function_records(buffer, sm_offset, num_funcs, func_offset):
    func_records = []
    for i in range(num_funcs):
        offset = sm_offset+func_offset+(i*FUNC_RECORD_SIZE)
        func_addr = struct.unpack('<Q', buffer[offset: offset+8])[0]
        stack_size = struct.unpack('<Q', buffer[offset+8: offset+16])[0]
        record_count = struct.unpack('<Q', buffer[offset+16: offset+24])[0]
        num_unwind = struct.unpack('<I', buffer[offset+24: offset+28])[0]
        unwind_offset = struct.unpack('<I', buffer[offset+28: offset+32])[0]
        func = FunctionRecord(func_addr, stack_size,
                              record_count, num_unwind, unwind_offset)
        func_records.append(func)
    return func_records


def parse_constants(buffer, sm_offset, num_constants, const_offset):
    constants = []
    for i in range(num_constants):
        offset = sm_offset + const_offset + (i*CONST_RECORD_SIZE)
        constant = struct.unpack('<Q', buffer[offset: offset+8])[0]
        constants.append(constant)
    return constants


def parse_call_site_records(buffer, sm_offset, num_records, record_offset):
    call_sites = []
    offset = sm_offset + record_offset
    for _ in range(num_records):
        id = struct.unpack('<Q', buffer[offset: offset+8])[0]
        func_idx = struct.unpack('<I', buffer[offset+8: offset+12])[0]
        offs = struct.unpack('<I', buffer[offset+12: offset+16])[0]
        reserved = struct.unpack('<H', buffer[offset+16: offset+18])[0]
        num_locations = struct.unpack('<H', buffer[offset+18: offset+20])[0]
        locations = parse_live_values(buffer, offset, num_locations, 20)
        padding = struct.unpack(
            '<H', buffer[offset+20+(num_locations*LIVE_VALUE_SIZE): offset+22+(num_locations*LIVE_VALUE_SIZE)])[0]
        num_live_outs = struct.unpack(
            '<H', buffer[offset+22+(num_locations*LIVE_VALUE_SIZE): offset+24+(num_locations*LIVE_VALUE_SIZE)])[0]
        live_outs = parse_live_outs(
            buffer, offset, num_live_outs, offset+24+(num_locations*LIVE_VALUE_SIZE))
        padding2 = struct.unpack('<H', buffer[offset+24+(num_locations*LIVE_VALUE_SIZE)+(
            num_live_outs*LIVE_OUT_RECORD_SIZE): offset+26+(num_locations*LIVE_VALUE_SIZE)+(num_live_outs*LIVE_OUT_RECORD_SIZE)])[0]
        num_arch_live = struct.unpack('<H', buffer[offset+26+(num_locations*LIVE_VALUE_SIZE)+(
            num_live_outs*LIVE_OUT_RECORD_SIZE): offset+28+(num_locations*LIVE_VALUE_SIZE)+(num_live_outs*LIVE_OUT_RECORD_SIZE)])[0]
        arch_lives = parse_arch_live(buffer, offset, num_arch_live, offset+28+(
            num_locations*LIVE_VALUE_SIZE)+(num_live_outs*LIVE_OUT_RECORD_SIZE))
        call_site = CallSiteRecord(id, func_idx, offs, reserved, num_locations, locations,
                                   padding, num_live_outs, live_outs, padding2, num_arch_live, arch_lives)
        offset += call_site.size()
        call_sites.append(call_site)
    return call_sites

def parse_live_values(buffer, cs_offset, num_locations, location_offset):
    live_vals = []
    for i in range(num_locations):
        offset = cs_offset + location_offset + (i*LIVE_VALUE_SIZE)
        val = buffer[offset]
        is_temp = val & 0b00000001
        is_dup = (val & 0b00000010) >> 1
        is_alloca = (val & 0b00000100) >> 2
        is_ptr = (val & 0b00001000) >> 3
        type = (val & 0b11110000) >> 4
        size = buffer[offset+1]
        regnum = struct.unpack('<H', buffer[offset+2: offset+4])[0]
        offset_or_const = struct.unpack('<i', buffer[offset+4: offset+8])[0]
        alloca_size = struct.unpack('<I', buffer[offset+8: offset+12])[0]
        live_val = LiveValue(is_temp, is_dup, is_alloca, is_ptr, type, size, regnum, offset_or_const, alloca_size)
        live_vals.append(live_val)
    return live_vals


def parse_live_outs(buffer, cs_offset, num_live_outs, lo_offset):
    live_outs = []
    for i in range(num_live_outs):
        offset = cs_offset + lo_offset + (i*LIVE_OUT_RECORD_SIZE)
        regnum = struct.unpack('<H', buffer[offset: offset+2])[0]
        reserved = struct.unpack('<B', buffer[offset+2: offset+3])[0]
        size = struct.unpack('<B', buffer[offset+3: offset+4])[0]
        live_out = LiveOutRecord(regnum, reserved, size)
        live_outs.append(live_out)
    return live_outs

def parse_arch_live(buffer, cs_offset, num_arch_live, al_offset):
    arch_lives = []
    for i in range(num_arch_live):
        offset = cs_offset + al_offset + (i*ARCH_LIVE_VALUE_SIZE)
        val = buffer[offset]
        is_ptr = val & 0b00000001
        bit_pad = (val & 0b00001110) >> 3
        type = (val & 0b11110000) >> 4
        size = buffer[offset+1]
        regnum = struct.unpack('<H', buffer[offset+2: offset+4])[0]
        offs = struct.unpack('<I', buffer[offset+4: offset+8])[0]
        val = buffer[offset+8]
        op_type = val & 0b00000111
        is_gen = (val & 0b00001000) >> 3
        inst_type = (val & 0b11110000) >> 4
        op_size = buffer[offset+9]
        op_regnum = struct.unpack('<H', buffer[offset+10: offset+12])[0]
        op_offset_or_const = struct.unpack('<q', buffer[offset+12: offset+20])[0]
        arch_live = ArchLiveValue(is_ptr, bit_pad, type, size, regnum, offs, op_type, is_gen, inst_type, op_size, op_regnum, op_offset_or_const)
        arch_lives.append(arch_live)
    return arch_lives