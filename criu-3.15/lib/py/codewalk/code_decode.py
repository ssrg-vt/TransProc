from collections import defaultdict
from pprint import pprint as pp
from elftools.elf.elffile import ELFFile
from capstone import *
from keystone import *
from capstone.x86 import *
from capstone.arm64 import *
import sys
import mmap
import contextlib
import re
import code
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils import elf_utils


class Disassemble:
    """ Class to disassemble either an ELF file or text segment 
    from CRIU dump. 

    Supported Architectures: X64 and ARM64
    """
    def __init__(self, filepath, start_address = None, end_address = None, arch = None):
        """ Class constructor with optional arguments (for ELF files).

        Args:
            filepath: Path to either ELF file or CRIU dump pages-(pages_id).img
            start_address: Start address of the binary file to disassemble.
            end_address: End address of the binary file to disassemble.
            arch: Machine architecture (x86 or ARM64)
        """
        self.filepath = filepath
        self.file = open(filepath, 'r+b')
        self.start_address = start_address
        self.end_address = end_address
        if arch is None:
            elffile = ELFFile(self.file)
            self.arch = elffile.get_machine_arch()
        else:
            self.arch = arch
        if self.arch.upper() in ('X64', 'X86', 'X86_64'):
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        elif self.arch.upper() in ('ARM64', 'ARM', 'AARCH64'):
            self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        else:
            raise Exception("Unsupported Architecture")

    def close(self):
        if self.file:
            self.file.close()
            self.file = None

    def disassemble_all(self):
        """ Disassemble all user defined functions in the file.
        """
        def banner(str):
            print('-' * len(str))

        try:
            if None in (self.start_address, self.end_address):
                func_info = elf_utils.find_functions(self.filepath)
                for func in func_info:
                    str = "Function: {}".format(func["name"])
                    banner(str)
                    print(str)
                    banner(str)
                    self.disassemble_range(int(func['saddr'][0], 0),
                                            int(func['eaddr'][0], 0))
            else:
                self.disassemble_range(self.start_address, self.end_address)
        except Exception as e:
            print('Could not process request: {}'.format(e))

    def disassemble_range(self, start_address, end_address):
        """ Disassemble function in the range provided as byte offset.
        
        Args:
            start_address: Byte offset to start disassembly.
            end_address: Byte offset to stop disassembly.
        """

        self.file.seek(start_address)
        data = self.file.read(end_address-start_address)
        for inst in self.md.disasm(data, start_address):
            print("0x%x:\t%s\t%s" %(inst.address, inst.mnemonic, inst.op_str))

    def get_local_offsets(self, start_address, end_address, refer_bp):
        """ Function to return list of local references in code which reference
        stack

        Args:
            start_address: Start address in pages-%.img to find instructions
            end_address: End address in pages-%.img to find instructions
            refer_bp: Use BP as reference for offset calculation
        Return:
            Returns a list of local reference info of the following type.
                [
                    {'code_offset' : Code offset of this instruction,
                    'stack_offset': Offset within the frame (RBP relative)
                    'size': Size of the memory access (QWORD/DWORD)
                    },
                ]
        """
        self.md.detail = True
        self.file.seek(start_address)
        data = self.file.read(end_address-start_address)
        info = list()
        for inst in self.md.disasm(data, start_address):
            if self.arch == 'X86_64':
                for opr in inst.operands:
                    if opr.type == X86_OP_MEM and \
                        opr.value.mem.base != 0 and \
                        opr.value.mem.disp != 0:
                            if inst.reg_name(opr.value.mem.base).upper() == 'RBP':
                                operands = "%s" %(inst.op_str)
                                inst_info = dict()
                                inst_info['code_offset'] =  inst.address
                                inst_info['stack_offset'] = opr.value.mem.disp
                                inst_info['size'] = 0x4 if 'dword' in operands else 0x8
                                info.append(inst_info)
            else:
                if len(inst.operands) >= 2:
                    opr = [op for op in inst.operands]
                    reg = ARM64_REG_X29 if refer_bp else ARM64_REG_SP
                    if opr[-1].reg == reg and \
                        opr[-1].type == ARM64_OP_MEM:
                        inst_info = dict()
                        inst_info['code_offset'] =  inst.address
                        inst_info['stack_offset'] = opr[-1].value.mem.disp
                        inst_info['size'] = 0x4 if opr[0].reg >= ARM64_REG_W0 and \
                                                    opr[0].reg <= ARM64_REG_W30 else 0x8
                        if len(inst.operands) == 3:
                                inst_info['size'] *= 2
                        info.append(inst_info)

        # filter those stack_offsets which have both Qword and Dword inst references.
        # certain runs of SNU cg fails without this filter
        # TODO: Exclude this filter for increased entropy                                                  
        offset_size = defaultdict(lambda: [0])
        for stack_info in info:
            if offset_size[stack_info['stack_offset']][-1] != stack_info['size']:
                offset_size[stack_info['stack_offset']].append(stack_info['size'])
        
        rem_offset = [stack_offset for stack_offset, size in offset_size.items() if len(size) > 2]
        info_filtered = [finfo for finfo in info if finfo['stack_offset'] not in rem_offset]
        
        return info_filtered

    def update_code_page(**kwargs):
        if kwargs['arch'] == 'X86_64':
            stack_offset1 = hex(kwargs['stack_offset1'])[3:]
            stack_offset2 = hex(kwargs['stack_offset2'])[3:]
        else:
            stack_offset1 = hex(kwargs['stack_offset1'])[2:]
            stack_offset2 = hex(kwargs['stack_offset2'])[2:]            
        code_offsets_exe = kwargs['code_offsets_exe']
        code_offsets_criu = kwargs['code_offsets_criu']

        with contextlib.closing(Disassemble(kwargs['path_exe'], arch = kwargs['arch'])) as disasm:
            with open(kwargs['path_exe'], 'r+b') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
                    try:
                        mv = memoryview(mm).cast('B')
                        for offset in code_offsets_exe:
                            mm.seek(offset)
                            # X86 Maximum instruction length is 15 Bytes
                            buffer = mm.read(0xf)
                            inst =  list(disasm.md.disasm(buffer , offset, 1))[0]
                            inst_size = inst.size
                            inst_address = inst.address
                            inst_old = "%s %s" %(inst.mnemonic, inst.op_str)
                            # Capstone may not prefix 0x to 1-digit hex values.
                            if stack_offset1 == '0' \
                                and kwargs['arch'] == 'AARCH64':
                                s_old = f"\[sp]"
                                s_new = f"[sp, #0x{stack_offset2}]"
                            else:
                                s_old = f"0?x?X?{stack_offset1}]"
                                s_new = f"0x{stack_offset2}]"                            
                            inst = re.sub(s_old, s_new, inst_old)    
                            inst = inst.encode()
                            if kwargs['arch'] == 'X86_64':
                                ks = Ks(KS_ARCH_X86, KS_MODE_64)
                            else:
                                ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
                            asm, _ = ks.asm(inst)
                            if len(asm) > inst_size:
                                raise Exception("Dst encoding sz > src encoding sz")
                            for b, value in enumerate(asm):
                                mv[offset + b] = value
                            if kwargs['arch'] == 'X86_64':
                                # For extra bytes in case destination encoding is smaller than
                                # source encoding replace with nop.
                                nop_enc, _ = ks.asm('nop')
                                for b in range(inst_size - len(asm)):
                                    mv[offset + len(asm) + b] = nop_enc[0]
                    finally:
                        del mv

        with contextlib.closing(Disassemble(kwargs['path_criu'], arch = kwargs['arch'])) as disasm:
            with open(kwargs['path_criu'], 'r+b') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
                    try:
                        mv = memoryview(mm).cast('B')
                        for offset in code_offsets_criu:
                            mm.seek(offset)
                            # X86 Maximum instruction length is 15 Bytes
                            buffer = mm.read(0xf)
                            inst =  list(disasm.md.disasm(buffer , offset, 1))[0]
                            inst_size = inst.size
                            inst_old = "%s %s" %(inst.mnemonic, inst.op_str)
                            # Capstone may not prefix 0x to 1-digit hex values.
                            if stack_offset1 == '0' \
                                and kwargs['arch'] == 'AARCH64':
                                s_old = f"\[sp]"
                                s_new = f"[sp, #0x{stack_offset2}]"
                            else:
                                s_old = f"0?x?X?{stack_offset1}]"
                                s_new = f"0x{stack_offset2}]"                            
                            inst = re.sub(s_old, s_new, inst_old)        
                            inst = inst.encode()
                            if kwargs['arch'] == 'X86_64':
                                ks = Ks(KS_ARCH_X86, KS_MODE_64)
                            else:
                                ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
                            asm, _ = ks.asm(inst)
                            if len(asm) > inst_size:
                                raise Exception("Dst encoding sz > src encoding sz")
                            for b, value in enumerate(asm):
                                mv[offset + b] = value
                            if kwargs['arch'] == 'X86_64':
                                # For extra bytes in case destination encoding is smaller than
                                # source encoding replace with nop.
                                nop_enc, _ = ks.asm('nop')
                                for b in range(inst_size - len(asm)):
                                    mv[offset + len(asm) + b] = nop_enc[0]
                    finally:
                        del mv        

    def feasible_code_page(**kwargs):
        """ Function to check if destination instruction encoding length is greater than
            source instruction encoding length. 
            If destination instruction encoding length is smaller, then the excess bytes are 
            replaced by nop.
        """
        arch = kwargs['arch']
        if arch == 'AARCH64':
            return True

        with contextlib.closing(Disassemble(kwargs['path'], arch = arch)) as disasm:
            disasm.md.detail = True
            for offset in kwargs['code_offsets']:
                disasm.file.seek(offset)
                # X86 Maximum instruction length is 15 Bytes
                buffer = disasm.file.read(0xf)
                inst =  list(disasm.md.disasm(buffer , offset, 1))[0]
                # Record source instruction length
                inst_size = inst.size
                inst = "%s %s" %(inst.mnemonic, inst.op_str)
                # Capstone may not prefix 0x to 1-digit hex values.
                s_old = f"0?x?X?{hex(kwargs['src_offset'])[3:]}]"
                s_new = f"0x{hex(kwargs['dst_offset'])[3:]}]"
                inst = re.sub(s_old, s_new, inst)
                inst = inst.encode()
                # TODO: Support ARM64
                ks = Ks(KS_ARCH_X86, KS_MODE_64)
                asm, _ = ks.asm(inst)
                # If destination instruction is longer than source instruction
                if len(asm) > inst_size:
                    return False
            
            return True

    def blk_stack_references(**kwargs):
        """ Function to blacklist any stack references based on instruction type.
            Function arguments referencing caller stack can be blocked when stack offsets
            with lea instructions are filtered
        """
        saddr = kwargs['saddr']
        eaddr = kwargs['eaddr']
        arch = kwargs['arch']
        blk_offsets = list()
        param_offsets = defaultdict(set)

        with contextlib.closing(Disassemble(kwargs['path'], arch = arch)) as disasm:
            disasm.md.detail = True
            disasm.file.seek(saddr)
            data = disasm.file.read(eaddr-saddr)
            for inst in disasm.md.disasm(data, saddr):
                if arch == 'X86_64':
                    for opr in inst.operands:
                        if  inst.id == X86_INS_LEA and \
                            opr.type == X86_OP_MEM and \
                            opr.value.mem.base != 0 and \
                            opr.value.mem.disp != 0:
                                if inst.reg_name(opr.value.mem.base).upper() == 'RBP':
                                    disp = opr.value.mem.disp
                                    blk_offsets.append(disp)
                else:
                    opr = [opr for opr in inst.operands]
                    if  len(inst.operands) == 3 and \
                        inst.reg_name(opr[1].value.mem.base).upper() == 'X29' and \
                        opr[1].type == ARM64_OP_REG and \
                        opr[2].type == ARM64_OP_IMM:
                            disp = opr[2].value.mem.base
                            blk_offsets.append(disp)

                    if  len(inst.operands) == 3 and \
                        opr[2].reg == ARM64_REG_X29 and \
                        (inst.id == ARM64_INS_STP or \
                        inst.id == ARM64_INS_LDP or \
                        inst.id == ARM64_INS_LDPSW):
                            disp = opr[2].value.mem.base
                            blk_offsets.append(disp)

                    if inst.id == ARM64_INS_BL:
                        func_info = elf_utils.find_functions(kwargs['path'])
                        saddr, eaddr = [(info['saddr']['exe_offset'] - 0x400000 ,info['eaddr']['exe_offset'] - 0x400000) 
                                for info in func_info 
                                if (info['saddr']['exe_offset'] - 0x400000) == opr[0].imm][0]
                        disasm.file.seek(saddr)
                        data = disasm.file.read(eaddr-saddr)
                        for inst in disasm.md.disasm(data, saddr):
                            if len(inst.operands) >= 2:
                                opr = [op for op in inst.operands]
                                if opr[-1].reg == ARM64_REG_X29 and \
                                    opr[-1].type == ARM64_OP_MEM and \
                                    opr[-1].value.mem.disp > 0:
                                        disp = opr[-1].value.mem.disp - 0x10
                                        blk_offsets.append(disp)
                                        param_offsets[saddr].add(disp)
         
        return blk_offsets, param_offsets

if __name__ == '__main__':
    for filepath in sys.argv[1:]:
        print('Filepath: {}'.format(filepath))
        with contextlib.closing(Disassemble(filepath)) as disasm:
            disasm.disassemble_all()