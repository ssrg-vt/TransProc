from collections import defaultdict, OrderedDict
from email.policy import default
import sys
import mmap
import random
import contextlib
import struct
import code
import time
from array import array
from pathlib import Path
from typing import Any, OrderedDict

from click import BadParameter
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils import elf_utils
from codewalk import code_decode
from pprint import pprint as pp

class StackFrame:
    """ Class representing a single stack frame.
    """
    def __init__(self):
        self.offset_sp = None
        self.offset_bp = None
        self.saddr = None
        self.eaddr = None
        self.func_name = None
        self.arch = None
        self.stack_inst = list()
        self.filepath = None
        
    def create_frame(self, sp, bp, func_name, local_info, filepath, path_exe, arch):
        """ Assign attributes to stack frame.

        Args:
            sp: Stack pointer offset (Relative to pages-%.img)
            bp: Base pointer offset (Relative to pages-%.img)
            func_name: Function this frame is pertaining to
            local_info: Information containing stack frame data
            filepath: Path to the criu dump
            path_exe: Path to the executable
            arch: Machine architecture
        """
        self.offset_sp = sp
        self.offset_bp = bp
        self.func_name = func_name
        self.local_info = local_info
        if arch.upper() not in ('X86_64', 'AARCH64',):
            raise Exception("Unsupported Architecture")
        self.arch = arch.upper()
        self.filepath = filepath
        self.path_exe = path_exe
        self.stack_offset = defaultdict(lambda: {'code_offset': [], 'size':0})

    def print_stack_frame(self):
        """ Print stack frame content.
        """
        print("SP Offset: 0x%x" % (self.offset_sp))
        print("BP Offset: 0x%x" % (self.offset_bp))
        print("Function: %s" % (self.func_name))
        print("Stack:")
        for cnt, val in enumerate(self.local_info['stack_data']):
            if self.arch == "X86_64":
                print("RBP-0x%03x\t0x%x" %(cnt*0x8,val))
            else:
                print("X29+0x%03x\t0x%x" %(cnt*0x8,val))
        print('-' * 30)

    def set_stack_locals(self, func_info):
        """ Function to obtain stack and corresponding code offsets.
        """


        for func in func_info:
            if func['name'] == self.func_name:
                with contextlib.closing(code_decode.Disassemble(self.path_exe,
                                                                arch = self.arch)) as disasm:
                    self.stack_inst = disasm.get_local_offsets(func['saddr']['exe_offset'],func['eaddr']['exe_offset'])
                    self.saddr = func['saddr']['exe_offset']
                    self.eaddr = func['eaddr']['exe_offset']

                if func['saddr']['criu_offset']:
                    with contextlib.closing(code_decode.Disassemble(self.filepath, 
                                                                    arch = self.arch)) as disasm:
                        offsets = disasm.get_local_offsets(func['saddr']['criu_offset'], 
                                                                    func['saddr']['criu_offset'] + func['saddr']['criu_size'])           
        
                        for offset in offsets:
                            self.stack_offset[offset['stack_offset']]['code_offset'].append(offset['code_offset'])
                            self.stack_offset[offset['stack_offset']]['size'] = offset['size']

                break

    def update_stack_reference(self,offset1, offset2,size):
        """ Function to update stack reference of offset1 to offset2.

        Args:
            offset1: Offset relative to pages-%.img of the first stack frame member
            offset2: Offset relative to pages-%.img of the second stack frame member
            size: Pointer size
        """
        with open(self.filepath, 'r+b') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE) as mm:
                try:
                    mv = memoryview(mm).cast('B')
                    # Using stack frame data previously saved during frame creation.
                    stack_data = self.local_info['stack_raw']
                    val = list(memoryview(stack_data).cast('B'))
                    if self.arch == 'X86_64':
                        # Reverse to keep it relative to RBP
                        val.reverse()
                        # Slice value at RBP (pushed stack frame) for easier indexing
                        val = val[8:]
                    for b in range(size):
                        # Update new stack offset to have location of old offset
                        try:
                            if self.arch == 'X86_64':
                                mv[offset2 + b] = val[self.offset_bp - offset1 -1 -b]
                            else:
                                mv[offset2 + b] = val[offset1 - self.offset_sp + b]
                        except:
                            print("Stack reference out of range!")
                            mv[offset2 + b] = 0                    
                finally:                    
                    del mv

    def update_frame(self, info):
        """ Update all stack references from give stack_offsets. 
            Stack_offset1's(old) content is copied to stack_offset2(new) location.
        """
        for stack_offset1, (stack_offset2, size) in info.items():
            if self.arch == 'X86_64':                      
                self.update_stack_reference(self.offset_bp + stack_offset1, 
                                            self.offset_bp + stack_offset2,
                                            size)
            else:
                self.update_stack_reference(self.offset_sp + stack_offset1, 
                                            self.offset_sp + stack_offset2,
                                            size)                

    def get_shuffled_offsets(src_offsets, path, arch):
        offset_list = [offset for offset in src_offsets.keys()]
        random.seed(time.time())
        random.shuffle(offset_list)
        it = iter(offset_list)
        offset_pair = list(zip(it,it))

        shuffled_offsets = [pair for pair in offset_pair if
                                    (code_decode.Disassemble.feasible_code_page(src_offset = pair[0],
                                                        dst_offset = pair[1],
                                                        code_offsets = src_offsets[pair[0]],
                                                        path = path,
                                                        arch = arch) and
                                    code_decode.Disassemble.feasible_code_page(src_offset = pair[1],
                                                        dst_offset = pair[0],
                                                        code_offsets = src_offsets[pair[1]],
                                                        path = path,
                                                        arch = arch))]

        return shuffled_offsets

    def shuffle_frame(self):
        """ Function to shuffle entire stack frame. 
            Obtain D-word and Q-word stack references for the frame by disassembling
            function from the criu dump. Separately shuffle stack offsets for D-word
            and Q-word and accordingly update both stack and code pages in the criu
            dump.
            Skip stack shuffling for PIE code such as from dynamic link library.
        """
        if '!PIE!' in self.func_name:
            return

        blk_offsets = code_decode.Disassemble.blk_stack_references(saddr = self.saddr, 
                                                                    eaddr = self.eaddr,
                                                                    path = self.path_exe,
                                                                    arch = self.arch)                                                                  
        
        shuffle_info = defaultdict(dict)
        # While building the stack code offset structure, if for any instructions referencing
        # the stack offset uses instructions blacklisted (eg., lea for call by address/reference)
        # then do not consider the stack offset for shuffling.
        # TODO: Instead of not considering the stack offset, but a reference tree using compiler to
        # identify callee functions and update the non-live (yet to be executed) references accordingly. 

        if self.arch == 'X86_64':
            d_ref = [{'stack_offset': inst['stack_offset'], 'code_offset': inst['code_offset']} 
                        for inst in self.stack_inst if inst['size'] == 0x4 and 
                                                    inst['stack_offset'] < 0 and
                                                    inst['stack_offset'] not in blk_offsets]

            q_ref = [{'stack_offset': inst['stack_offset'], 'code_offset': inst['code_offset']} 
                        for inst in self.stack_inst if inst['size'] == 0x8 and
                                                    inst['stack_offset'] < 0 and 
                                                    inst['stack_offset'] not in blk_offsets]
        else:
            d_ref = [{'stack_offset': inst['stack_offset'], 'code_offset': inst['code_offset']} 
                        for inst in self.stack_inst if inst['size'] == 0x4 and 
                                                    inst['stack_offset'] >= 0 and
                                                    inst['stack_offset'] not in blk_offsets]

            q_ref = [{'stack_offset': inst['stack_offset'], 'code_offset': inst['code_offset']} 
                        for inst in self.stack_inst if inst['size'] == 0x8 and
                                                    inst['stack_offset'] >= 0 and 
                                                    inst['stack_offset'] not in blk_offsets]      
                   
        d_offset = defaultdict(list)
        for ref in d_ref:
            d_offset[ref['stack_offset']].append(ref['code_offset'])
        d_shuffle_list = StackFrame.get_shuffled_offsets(d_offset, self.path_exe, self.arch)
        q_offset = defaultdict(list)
        for ref in q_ref:
            if ref['stack_offset'] in d_offset.keys():
                d_offset[ref['stack_offset']].append(ref['code_offset'])
            else:
                q_offset[ref['stack_offset']].append(ref['code_offset'])
        q_shuffle_list = StackFrame.get_shuffled_offsets(q_offset, self.path_exe, self.arch)

        print(f"Function: {self.func_name}")
        tsref = sum([len(offset) for offset in d_offset.values()]) + \
                    sum([len(offset) for offset in q_offset.values()])
        print(f"  Total stack ref   : {tsref}")
        ssref = sum ([len(d_offset[offset[0]]) + len(d_offset[offset[1]]) for offset in d_shuffle_list]) + \
                    sum ([len(q_offset[offset[0]]) + len(q_offset[offset[1]]) for offset in q_shuffle_list])
        print(f"  Shuffled Stack ref: {ssref}")

        # For every stack offset, pair with new offset and accordingly modify
        # stack and code pages
        for stack_offset1, stack_offset2 in q_shuffle_list:
            print(f"  Shuffle Offsets: {hex(stack_offset1)} <--> {hex(stack_offset2)}")
            shuffle_info[self.func_name][stack_offset1] = (stack_offset2, 0x8)
            shuffle_info[self.func_name][stack_offset2] = (stack_offset1, 0x8) 
            if self.arch == 'X86_64':                   
                self.update_stack_reference(self.offset_bp + stack_offset1, 
                                            self.offset_bp + stack_offset2,
                                            0x8)
                self.update_stack_reference(self.offset_bp + stack_offset2, 
                                            self.offset_bp + stack_offset1,
                                            0x8)      
            else:               
                self.update_stack_reference(self.offset_sp + stack_offset1, 
                                            self.offset_sp + stack_offset2,
                                            0x8)
                self.update_stack_reference(self.offset_sp + stack_offset2, 
                                            self.offset_sp + stack_offset1,
                                            0x8)    

            code_decode.Disassemble.update_code_page(stack_offset1 = stack_offset1,
                                                        stack_offset2 = stack_offset2,
                                                        code_offsets_exe = q_offset[stack_offset1],
                                                        code_offsets_criu = self.stack_offset[stack_offset1]['code_offset'],
                                                        path_exe = self.path_exe,
                                                        path_criu = self.filepath,
                                                        arch = self.arch)

            code_decode.Disassemble.update_code_page(stack_offset1 = stack_offset2,
                                                        stack_offset2 = stack_offset1,
                                                        code_offsets_exe = q_offset[stack_offset2],
                                                        code_offsets_criu = self.stack_offset[stack_offset2]['code_offset'],
                                                        path_exe = self.path_exe,
                                                        path_criu = self.filepath,
                                                        arch = self.arch)

        # Repeat the same for D-word stack references.    
        for stack_offset1, stack_offset2 in d_shuffle_list:
            print(f"  Shuffle Offsets: {hex(stack_offset1)} <--> {hex(stack_offset2)}")
            shuffle_info[self.func_name][stack_offset1] = (stack_offset2, 0x4)
            shuffle_info[self.func_name][stack_offset2] = (stack_offset1, 0x4)
            if self.arch == 'X86_64':     
                self.update_stack_reference(self.offset_bp + stack_offset1, 
                                            self.offset_bp + stack_offset2,
                                            0x4)
                self.update_stack_reference(self.offset_bp + stack_offset2, 
                                            self.offset_bp + stack_offset1,
                                            0x4)    
            else:
                self.update_stack_reference(self.offset_sp + stack_offset1, 
                                            self.offset_sp + stack_offset2,
                                            0x4)
                self.update_stack_reference(self.offset_sp + stack_offset2, 
                                            self.offset_sp + stack_offset1,
                                            0x4)    

            code_decode.Disassemble.update_code_page(stack_offset1 = stack_offset1,
                                                        stack_offset2 = stack_offset2,
                                                        code_offsets_exe = d_offset[stack_offset1],
                                                        code_offsets_criu = self.stack_offset[stack_offset1]['code_offset'],
                                                        path_exe = self.path_exe,
                                                        path_criu = self.filepath,
                                                        arch = self.arch)

            code_decode.Disassemble.update_code_page(stack_offset1 = stack_offset2,
                                                        stack_offset2 = stack_offset1,
                                                        code_offsets_exe = d_offset[stack_offset2],
                                                        code_offsets_criu = self.stack_offset[stack_offset2]['code_offset'],
                                                        path_exe = self.path_exe,
                                                        path_criu = self.filepath,
                                                        arch = self.arch)                                                     
        
        return shuffle_info
                                                         

class Stack:
    """ Class to represent stack of the checkpointed process.
    """
    def __init__(self, filepath, ip, sp, offset_sp, offset_bp, func_info, func_info_img, path_exe = None, arch = None):
        """ Class constructor to repsent entire stack read from pages-%.img.

        Args:
            filepath: Path to the pages-%.img containing stack data
            ip: Instruction pointer executing in the context of top stack frame
            sp: Stack pointer register value (Machine reg value)
            offset_sp: Stack pointer offset relative to pages-%.img
            offset_bp: Base pointer offset relative to pages-%.img
            path_exe: Path to the elf executable
            func_info: Function name and start/end address after pagemap offset
        """
        self.ip = ip
        self.sp_run = sp
        self.filepath = filepath  
        self.file = open(filepath, 'rb')
        self.offset_sp = offset_sp
        self.offset_bp = offset_bp
        self.func_info = func_info
        self.func_info_img = func_info_img
        self.path_exe = path_exe
        if arch.upper() not in ('X86_64', 'AARCH64',):
            raise Exception("Unsupported Architecture")
        self.arch = arch.upper()

    def close(self):
        if self.file:
            self.file.close()
            self.file = None

    def get_function_name(self, address):
        """ Get function name given the function address from the vma.

        Arg:
            address: function address from the vma
        """
        for func in self.func_info_img:
            if func['saddr']['exe_offset'] <= (address - 0x400000) < func['eaddr']['exe_offset']:
                return func['name']


    def iterate_frame(self):
        """ Iterate through the stack frame starting from top most frame
        and iterating till stack frame of main function.
        """
        sp = self.offset_sp
        if self.arch == 'X86_64':
            bp = self.offset_bp
        else:
            bp = self.offset_bp + 0x8
        ip = self.ip
        while True:
            # bp is 0 for the main function 
            if bp == 0:
                return
            
            self.file.seek(sp)
            try:
                frame_content = self.file.read(bp-sp+0x8)
            except:
                raise Exception("BP < SP: Check if frame pointer is enabled.")
            # Obtain stack content as Qword array
            val = list(memoryview(frame_content).cast('Q'))
            # Reverse list to represent RBP as the lowest index in the list
            if self.arch == 'X86_64':
                val.reverse()
            name = self.get_function_name(ip)
            name = '!PIE! 0x%0x' % (ip) if name is None else name
            if self.arch == 'X86_64':
                ip = struct.unpack('<Q', self.file.read(0x8))[0]
            else:
                ip = val[-1]
            local_info = dict()
            # stac_data contains Quad word starting from BP in both
            # x86_64 and AARCH64
            local_info['stack_data'] = val
            local_info['stack_raw'] = frame_content
            frame = StackFrame()
            frame.create_frame(sp, bp, name, local_info, self.filepath, self.path_exe, self.arch)
            frame.set_stack_locals(self.func_info_img)    

            yield frame

            # Next sp is 2 QWORDS away from current bp for x86_64
            sp = bp-0x10 if self.arch == 'X86_64' else bp+0x8
            
            if self.arch == 'X86_64':
                # Get next bp by reading content at current frames bp and then
                # adjusting that value to represent offset within pages-%.img
                bp = 0 if not val[0] else (val[0]-self.sp_run) + self.offset_sp
            else:
                bp = 0 if not val[-2] else (val[-2] + 0x8 - self.sp_run) + self.offset_sp

    def view_all(self):
        """ View all the stack frames of the checkpointed process.
        """
        for frame in self.iterate_frame():
            frame.print_stack_frame()

    def shuffle_all(self):
        """ Shuffle all stack frames in the criu dump. 
        """
        shuffled_frames = dict()
        # TODO: Skipping top_frame shuffle is causing segfault in ft and mg NPB serial
        # benchmark. Fix this and consider top_frame for shuffling.
        top_frame = None
        for frame in self.iterate_frame():
            # If stack frame previously shuffled, then do not update code but shuffle
            # only the stack frame. Used for recursive functions.
            if top_frame is None:
                top_frame = frame
            if frame.func_name in shuffled_frames.keys():
                frame.update_frame(shuffled_frames[frame.func_name])
            else:
                info = frame.shuffle_frame()                    
                if info is not None:
                    shuffled_frames.update(info)

