from pycriu import stack_map_utils
from pycriu import elf_utils


X86_64 = 0
AARCH64 = 1


class StHandle:
    def __init__(self, core, elffile):
        if core['mtype'] == 'X86_64':
            self.type = X86_64
        elif core['mtype'] == 'AARCH64':
            self.type = AARCH64
        else:
            raise Exception("Architecture not supported")

        section = elf_utils.get_elf_section(elffile, stack_map_utils.UNWIND_ADDR_SECTION)
        self.unw_addr_entries = elf_utils.get_num_entries(section)
        if self.unw_addr_entries > 0:
            self.unwind_addrs = stack_map_utils.parse_unwind_addrs(section)
        
        section = elf_utils.get_elf_section(elffile, stack_map_utils.UNWIND_SECTION)
        self.unw_loc_entries = elf_utils.get_num_entries(section)
        if self.unw_loc_entries > 0:
            self.unwind_locs = stack_map_utils.parse_unwind_locs(section)

        section = elf_utils.get_elf_section(elffile, stack_map_utils.ID_SECTION)
        self.cs_id_entries = elf_utils.get_num_entries(section)
        if self.cs_id_entries > 0:
            self.call_sites_id = stack_map_utils.parse_call_sites_by_id(section)
        
        section = elf_utils.get_elf_section(elffile, stack_map_utils.ADDR_SECTION)
        self.cs_addr_entries = elf_utils.get_num_entries(section)
        if self.cs_addr_entries > 0:
            self.call_sites_addr = stack_map_utils.parse_call_sites_by_addr(section)

        section = elf_utils.get_elf_section(elffile, stack_map_utils.LIVE_VALUE_SECTION)
        self.live_val_entries = elf_utils.get_num_entries(section)
        if self.live_val_entries > 0:
            self.live_vals = stack_map_utils.parse_live_values(section)
        
        section = elf_utils.get_elf_section(elffile, stack_map_utils.ARCH_LIVE_SECTION)
        self.arch_live_entries = elf_utils.get_num_entries(section)
        if self.arch_live_entries > 0:
            self.arch_live_vals = stack_map_utils.parse_arch_live_values(section)


class RewriteContext:
    def __init__(self, st_handle, stack_base, stack_top, regset, num_acts, ):
        pass