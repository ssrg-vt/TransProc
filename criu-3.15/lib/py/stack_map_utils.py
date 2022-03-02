import code
from collections import defaultdict
from email.policy import default
import struct
import sys

STACKMAP_SECTION = '.llvm_pcn_stackmaps'
ST_PREFIX = '.stack_transform'
UNWIND_ADDR_SECTION = ST_PREFIX + '.unwind_arange'
UNWIND_SECTION = ST_PREFIX + '.unwind'
ID_SECTION = ST_PREFIX + '.id'
ADDR_SECTION = ST_PREFIX + '.addr'
LIVE_VALUE_SECTION = ST_PREFIX + '.live'
ARCH_LIVE_SECTION = ST_PREFIX + '.arch_const'

FUNC_RECORD_SIZE = 32
CONST_RECORD_SIZE = 8
LIVE_VALUE_SIZE = 12
ARCH_LIVE_VALUE_SIZE = 20
LIVE_OUT_RECORD_SIZE = 4

class UnwindAddr:
    def __init__(self, addr, num_unwind, unwind_offset):
        self.addr = addr
        self.num_unwind = num_unwind
        self.unwind_offset = unwind_offset
    
    def print_vals(self):
        print("Unwind Addr: 0x%lx, number of unwinding entries: %d, offset into unwinding section: %d" % (self.addr, self.num_unwind, self.unwind_offset))


class UnwindLoc:
    def __init__(self, regnum, offset):
        self.reg = regnum
        self.offset = offset

    def print_vals(self):
        print("Register: %d + %d" % (self.reg, self.offset))


class CallSite:
    def __init__(self, id, addr, frame_size, num_unwind, unwind_offset, num_live, live_offset, num_arch_live, arch_live_offset):
        self.id = id
        self.addr = addr
        self.frame_size = frame_size
        self.num_unwind = num_unwind
        self.unwind_offset = unwind_offset
        self.num_live = num_live
        self.live_offset = live_offset
        self.num_arch_live = num_arch_live
        self.arch_live_offset = arch_live_offset
    
    def print_vals(self):
        print("Call site %ld: addr=0x%lx, frame size=%d, num unwind=%d, unwind offset=%ld, num live=%d, live offset=%ld, num arch live=%d, arch live offset=%ld" %
        (self.id, self.addr, self.frame_size, self.num_unwind, self.unwind_offset, self.num_live, self.live_offset, self.num_arch_live, 
        self.arch_live_offset))


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

    def print_val(self):
        string = "    Location: size: %d, in register %d" % (self.size, self.regnum)
        if self.type != 1:
            string += "+ %d" % (self.offset_or_const)
        if self.is_temp:
            string += ", is temporary"
        if self.is_duplicate:
            string += ", is duplicate"
        if self.is_alloca:
            string += ", is alloca of size %d byte(s)" % (
                self.alloca_size)
        if self.is_ptr:
            string += ", is a pointer"
        print(string)

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
    
    def print_val(self):
        string = "    Arch specific location: size %d, in register %d + %d, type: %d, operand type: %d, inst type: %d, operand size: %d, operand reg: %d + %ld" % \
            (self.size, self.regnum, self.offset, self.type, self.operand_type, self.inst_type,
                self.operand_size, self.operand_regnum, self.operand_offset_or_constant)
        if self.is_ptr:
            string += ", is a pointer"
        if self.is_gen:
            string += ", is gen"
        print(string)


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
        return 28 + (self.num_locations * LIVE_VALUE_SIZE) + \
            (self.num_live_outs * LIVE_OUT_RECORD_SIZE) + \
            (self.num_arch_live * ARCH_LIVE_VALUE_SIZE)


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


def print_stack_map_data(stack_maps):
    print("Found %d stackmaps" % len(stack_maps))
    for sm in stack_maps:
        print("Stackmap v%d: %d functions, %d constants, %d call sites" %
              (sm.version, sm.num_functions, sm.num_constants, sm.num_records))
        for i in range(len(sm.function_records)):
            func = sm.function_records[i]
            print("  Function %d: address=0x%lx, stack size=%ld, number of unwinding entries: %d, offset into unwinding section: %d" %
                  (i, func.function_addr, func.stack_size, func.num_unwind, func.unwind_offset))
        for i in range(len(sm.constants)):
            print("  Constant %d: %ld" % (i, sm.constants[i]))
        for cs in sm.call_sites:
            print("  Call site %d: function %d, offset @ %d, %d locations, %d live-outs, %d arch-specific locations" % (cs.id, cs.func_idx, cs.offset,
                                                                                                                        cs.num_locations, cs.num_live_outs, cs.num_arch_live))
            for loc in cs.location:
                loc.print_val()
            for lo in cs.live_outs:
                print("    Live Out: in register %d and size %d" %
                      (lo.regnum, lo.size))
            for al in cs.arch_live:
                al.print_val()


def parse_stack_maps(section, arch = None):
    assert section.name == STACKMAP_SECTION
    buffer = section.data()
    sm_info = defaultdict(lambda:{'id' : -1, 'stack_size' : -1 ,'stack_offsets' : {}})
    offset = 0
    stack_maps = []
    py_ver = sys.version_info
    while offset < section.data_size:
        if py_ver.major == 3:
            version = buffer[offset]
        else:
            version = struct.unpack('<B', buffer[offset])[0]
        reserved = buffer[offset+1]
        reserved2 = struct.unpack('<H', buffer[offset+2:offset+4])[0]
        num_funcs = struct.unpack('<I', buffer[offset+4:offset+8])[0]
        num_constants = struct.unpack('<I', buffer[offset+8:offset+12])[0]
        num_records = struct.unpack('<I', buffer[offset+12:offset+16])[0]
        func_records = _parse_function_records(buffer, offset, num_funcs, 16)
        for idx, record in enumerate(func_records):
            sm_info[record.function_addr]['id'] = idx
            sm_info[record.function_addr]['stack_size'] = record.stack_size
        constants = _parse_constants(
            buffer, offset, num_constants, 16+(num_funcs*FUNC_RECORD_SIZE))
        (call_sites, offset, cs_info) = _parse_call_site_records(buffer, offset, num_records, 16+(
            num_funcs*FUNC_RECORD_SIZE)+(num_constants*CONST_RECORD_SIZE), arch)
        for address in sm_info.keys():
            sm_info[address]['stack_offsets'].update(cs_info[sm_info[address]['id']])
        sm_info[record.function_addr]
        stack_map = StackMap(version, reserved, reserved2, num_funcs,
                             num_constants, num_records, func_records, constants, call_sites)
        stack_maps.append(stack_map)
        
    return stack_maps, sm_info


def parse_unwind_addrs(section, dump = False):
    assert section.name == UNWIND_ADDR_SECTION
    buffer = section.data()
    unwind_addrs = []
    offset = 0
    while offset < section.data_size:
        addr = struct.unpack('<Q', buffer[offset: offset+8])[0]
        num_unw = struct.unpack('<I', buffer[offset+8: offset+12])[0]
        unw_offs = struct.unpack('<I', buffer[offset+12: offset+16])[0]
        unw_addr = UnwindAddr(addr, num_unw, unw_offs)
        if dump:
            unw_addr.print_vals()
        unwind_addrs.append(unw_addr)
        offset += 16
    return unwind_addrs


def parse_unwind_locs(section, dump = False):
    assert section.name == UNWIND_SECTION
    buffer = section.data()
    unwind_locs = []
    offset = 0
    while offset < section.data_size:
        reg = struct.unpack('<H', buffer[offset: offset+2])[0]
        offs = struct.unpack('<h', buffer[offset+2: offset+4])[0]
        unw_loc = UnwindLoc(reg, offs)
        if dump:
            unw_loc.print_vals()
        unwind_locs.append(unw_loc)
        offset += 4
    return unwind_locs


def parse_live_values(section, num_live_vals, dump = False):
    assert section.name == LIVE_VALUE_SECTION
    buffer = section.data()
    live_vals, _ = _parse_live_values(buffer, 0, num_live_vals, 0)
    if dump:
        for l in live_vals:
            l.print_val()
    return live_vals

def parse_arch_live_values(section, num_arch, dump = False):
    assert section.name == ARCH_LIVE_SECTION
    buffer = section.data()
    arch_live_vals = _parse_arch_live(buffer, 0, num_arch, 0)
    if dump:
        for al in arch_live_vals:
            al.print_val()
    return arch_live_vals


def parse_call_sites_by_id(section, dump = False):
    assert section.name == ID_SECTION
    return _parse_call_sites(section, dump)


def parse_call_sites_by_addr(section, dump = False):
    assert section.name == ADDR_SECTION
    return _parse_call_sites(section, dump)


def _parse_call_sites(section, dump = False):
    assert (section.name == ID_SECTION) or (section.name == ADDR_SECTION)
    buffer = section.data()
    call_sites = []
    offset = 0
    while offset < section.data_size:
        id = struct.unpack('<Q', buffer[offset: offset+8])[0]
        addr = struct.unpack('<Q', buffer[offset+8: offset+16])[0]
        frame_size = struct.unpack('<I', buffer[offset+16: offset+20])[0]
        num_unwind = struct.unpack('<H', buffer[offset+20: offset+22])[0]
        unwind_offset = struct.unpack('<Q', buffer[offset+22: offset+30])[0]
        num_live = struct.unpack('<H', buffer[offset+30: offset+32])[0]
        live_offset = struct.unpack('<Q', buffer[offset+32: offset+40])[0]
        num_arch_live = struct.unpack('<H', buffer[offset+40: offset+42])[0]
        arch_live_offset = struct.unpack('<Q', buffer[offset+42: offset+50])[0]
        cs = CallSite(id, addr, frame_size, num_unwind, unwind_offset, num_live, live_offset, num_arch_live, arch_live_offset)
        if dump:
            cs.print_vals()
        call_sites.append(cs)
        offset += 52
    return call_sites


def _parse_function_records(buffer, sm_offset, num_funcs, func_offset):
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


def _parse_constants(buffer, sm_offset, num_constants, const_offset):
    constants = []
    for i in range(num_constants):
        offset = sm_offset + const_offset + (i*CONST_RECORD_SIZE)
        constant = struct.unpack('<Q', buffer[offset: offset+8])[0]
        constants.append(constant)
    return constants


def _parse_call_site_records(buffer, sm_offset, num_records, record_offset, arch = None):
    call_sites = []
    offset = sm_offset + record_offset
    cs_info = defaultdict(lambda: defaultdict(list))
    for _ in range(num_records):
        id = struct.unpack('<Q', buffer[offset: offset+8])[0]
        func_idx = struct.unpack('<I', buffer[offset+8: offset+12])[0]
        offs = struct.unpack('<I', buffer[offset+12: offset+16])[0]
        reserved = struct.unpack('<H', buffer[offset+16: offset+18])[0]
        num_locations = struct.unpack('<H', buffer[offset+18: offset+20])[0]
        locations, offset_infos = _parse_live_values(buffer, offset, num_locations, 20, arch)
        padding = struct.unpack(
            '<H', buffer[offset+20+(num_locations*LIVE_VALUE_SIZE): offset+22+(num_locations*LIVE_VALUE_SIZE)])[0]
        num_live_outs = struct.unpack(
            '<H', buffer[offset+22+(num_locations*LIVE_VALUE_SIZE): offset+24+(num_locations*LIVE_VALUE_SIZE)])[0]
        live_outs = _parse_live_outs(
            buffer, offset, num_live_outs, 24+(num_locations*LIVE_VALUE_SIZE))
        padding2 = struct.unpack('<H', buffer[offset+24+(num_locations*LIVE_VALUE_SIZE)+(
            num_live_outs*LIVE_OUT_RECORD_SIZE): offset+26+(num_locations*LIVE_VALUE_SIZE)+(num_live_outs*LIVE_OUT_RECORD_SIZE)])[0]
        num_arch_live = struct.unpack('<H', buffer[offset+26+(num_locations*LIVE_VALUE_SIZE)+(
            num_live_outs*LIVE_OUT_RECORD_SIZE): offset+28+(num_locations*LIVE_VALUE_SIZE)+(num_live_outs*LIVE_OUT_RECORD_SIZE)])[0]
        arch_lives = _parse_arch_live(buffer, offset, num_arch_live, 28+(
            num_locations*LIVE_VALUE_SIZE)+(num_live_outs*LIVE_OUT_RECORD_SIZE))
        call_site = CallSiteRecord(id, func_idx, offs, reserved, num_locations, locations,
                                   padding, num_live_outs, live_outs, padding2, num_arch_live, arch_lives)
        offset += call_site.size()
        if offset % 8 != 0:
            offset += 4
        call_sites.append(call_site)
        for stack_offset, section_offset in offset_infos:
            cs_info[func_idx][stack_offset].append(section_offset)
    return (call_sites, offset, cs_info)


def _parse_live_values(buffer, cs_offset, num_locations, location_offset, arch = None):
    live_vals = []
    offset_infos = []
    py_ver = sys.version_info
    for i in range(num_locations):
        offset = cs_offset + location_offset + (i*LIVE_VALUE_SIZE)
        if py_ver.major == 3:
            val = buffer[offset]
            size = buffer[offset+1]
        else:
            val = struct.unpack('<B', buffer[offset])[0]
            size = struct.unpack('<B', buffer[offset+1])[0]
        is_temp = val & 0b00000001
        is_dup = (val & 0b00000010) >> 1
        is_alloca = (val & 0b00000100) >> 2
        is_ptr = (val & 0b00001000) >> 3
        type = (val & 0b11110000) >> 4
        regnum = struct.unpack('<H', buffer[offset+2: offset+4])[0]
        offset_or_const = struct.unpack('<i', buffer[offset+4: offset+8])[0]

        if arch == 'X86_64':
            if regnum == 6 and type != 1:
                offset_infos.append((offset_or_const, offset+4))
        elif arch == 'AARCH64':
            if regnum == 29 and type != 1:
                offset_infos.append((offset_or_const, offset+4))
        alloca_size = struct.unpack('<I', buffer[offset+8: offset+12])[0]
        live_val = LiveValue(is_temp, is_dup, is_alloca, is_ptr,
                             type, size, regnum, offset_or_const, alloca_size)
        live_vals.append(live_val)
    return live_vals, offset_infos


def _parse_live_outs(buffer, cs_offset, num_live_outs, lo_offset):
    live_outs = []
    for i in range(num_live_outs):
        offset = cs_offset + lo_offset + (i*LIVE_OUT_RECORD_SIZE)
        regnum = struct.unpack('<H', buffer[offset: offset+2])[0]
        reserved = struct.unpack('<B', buffer[offset+2: offset+3])[0]
        size = struct.unpack('<B', buffer[offset+3: offset+4])[0]
        live_out = LiveOutRecord(regnum, reserved, size)
        live_outs.append(live_out)
    return live_outs


def _parse_arch_live(buffer, cs_offset, num_arch_live, al_offset):
    arch_lives = []
    py_ver = sys.version_info
    for i in range(num_arch_live):
        offset = cs_offset + al_offset + (i*ARCH_LIVE_VALUE_SIZE)
        if py_ver.major == 3:
            val = buffer[offset]
            size = buffer[offset+1]
        else:
            val = struct.unpack('<B', buffer[offset])[0]
            size = struct.unpack('<B', buffer[offset+1])[0]
        is_ptr = val & 0b00000001
        bit_pad = (val & 0b00001110) >> 1
        type = (val & 0b11110000) >> 4
        regnum = struct.unpack('<H', buffer[offset+2: offset+4])[0]
        offs = struct.unpack('<I', buffer[offset+4: offset+8])[0]
        if py_ver.major == 3:
            val = buffer[offset+8]
            op_size = buffer[offset+9]
        else:
            val = struct.unpack('<B', buffer[offset+8])[0]
            op_size = struct.unpack('<B', buffer[offset+9])[0]
        op_type = val & 0b00000111
        is_gen = (val & 0b00001000) >> 3
        inst_type = (val & 0b11110000) >> 4
        op_regnum = struct.unpack('<H', buffer[offset+10: offset+12])[0]
        op_offset_or_const = struct.unpack(
            '<q', buffer[offset+12: offset+20])[0]
        arch_live = ArchLiveValue(is_ptr, bit_pad, type, size, regnum, offs,
                                  op_type, is_gen, inst_type, op_size, op_regnum, op_offset_or_const)
        arch_lives.append(arch_live)
    return arch_lives
