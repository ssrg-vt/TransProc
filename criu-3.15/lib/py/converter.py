# Current version by Abhishek Bapat. SSRG, Virginia Tech 2021.
# abapat28@vt.edu

from os.path import isfile, join
from os import listdir
from copy import copy
from abc import ABCMeta, abstractmethod
from collections import OrderedDict
from ctypes import *

import shutil
import struct
import os
import sys
import pycriu

from pycriu import elf_utils
from pycriu import definitions
from pycriu.definitions import StHandle, RewriteContext
from pycriu.st_reg_transform import rewrite_frame, unwind_and_size
from pycriu import reg_x86_64, reg_aarch64

class Reg64(Structure):
    _fields_ = [("x", c_ulonglong)]
class Reg128(Structure):
    _fields_ = [("x", c_ulonglong), ("y", c_ulonglong)]
class Aarch64Struct(Structure):
    _fields_ = [("magic", c_ulonglong), ("sp", c_ulonglong), 
    ("pc", c_ulonglong), ("regs", Reg64 * 31), ("vregs", Reg128 * 32)]

class X86Struct(Structure):
    _fields_ = [("magic", c_ulonglong), ("rip", c_ulonglong)]
    gregs=["rax","rdx","rcx","rbx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15"]
    for grn in gregs:
        _fields_.append((grn, c_ulonglong))
    _fields_.append(("mmx", Reg64*8)) 
    _fields_.append(("xmm", Reg128*16)) 
    _fields_.append(("st", c_longdouble*8)) 
    csregs=["cs","ss","ds","es","fs","gs"]
    for grn in csregs:
        _fields_.append((grn, c_uint32))
    _fields_.append(("rflags", c_uint64))

def ordered_dict_prepend(dct, key, value, dict_setitem=dict.__setitem__):
    if sys.version_info[0] < 3:
        root = dct._OrderedDict__root
        first = root[1]
        if key in dct:
            link = dct._OrderedDict__map[key]
            link_prev, link_next, _ = link
            link_prev[1] = link_next
            link_next[0] = link_prev
            link[0] = root
            link[1] = first
            root[1] = first[0] = link
        else:
            root[1] = first[0] = dct._OrderedDict__map[key] = [root, first, key]
            dict_setitem(dct, key, value)
    else:
        dct[key] = value
        dct.move_to_end(key, last=False)

def align(val, size=4096):
    t = ((val + (size-1)) & ~(size-1))
    return t

X8664_SUFFIX = '_x86-64'
AARCH64_SUFFIX = '_aarch64'

AARCH64 = 'AARCH64'
X8664 = 'X86_64'

CGROUP = 'cgroup'
CORE = 'core'
FDINFO = 'fdinfo'
FILES = 'files'
FS = 'fs'
IDS = 'ids'
INVENTORY = 'inventory'
MM = 'mm'
PAGEMAP = 'pagemap'
PSTREE = 'pstree'
SECCOMP = 'seccomp'
TIMENS = 'timens'
TTYINFO = 'tty-info'
PAGES = 'pages'

PAGESIZE = 4096


class Converter():  # TODO: Extend the logic for multiple PIDs
    __metaclass__ = ABCMeta

    def __init__(self, src_dir, dest_dir, src_bin, bin_dir, debug):
        assert os.path.exists(src_dir), "Source directory does not exist"
        assert os.path.exists(
            join(src_dir, src_bin)), "Source binary does not exist"
        assert os.path.exists(join(bin_dir, src_bin+'_x86-64')
                              ), "Binary x86-64 copy does not exist"
        assert os.path.exists(join(bin_dir, src_bin+'_aarch64')
                              ), "Binary aarch64 copy does not exist"
        self.arch = None
        self.debug = debug
        self.images = {}
        self.src_dir = src_dir
        self.dest_dir = dest_dir
        self.bin_dir = bin_dir
        self.bin = src_bin
        self.entry_num = 0
        self.altered_regions = dict()
        self.files_per_pid = [
            IDS,
            MM,
            CORE,
            FS,
            PAGEMAP,
        ]
        self.src_image_file_paths = dict()
        self.dest_image_file_paths = dict()
        self.src_rewrite_ctx = None
        self.dest_rewrite_ctx = None
        img_files = [f for f in listdir(src_dir) if (
            isfile(join(src_dir, f)) and "img" in f)]
        for f in img_files:
            if CGROUP in f:
                self.src_image_file_paths[CGROUP] = join(src_dir, f)
                self.dest_image_file_paths[CGROUP] = join(dest_dir, f)
            if CORE in f:
                self.src_image_file_paths[CORE] = join(src_dir, f)
                self.dest_image_file_paths[CORE] = join(dest_dir, f)
            if FDINFO in f:
                self.src_image_file_paths[FDINFO] = join(src_dir, f)
                self.dest_image_file_paths[FDINFO] = join(dest_dir, f)
            if FILES in f:
                self.src_image_file_paths[FILES] = join(src_dir, f)
                self.dest_image_file_paths[FILES] = join(dest_dir, f)
            if FS in f:
                self.src_image_file_paths[FS] = join(src_dir, f)
                self.dest_image_file_paths[FS] = join(dest_dir, f)
            if IDS in f:
                self.src_image_file_paths[IDS] = join(src_dir, f)
                self.dest_image_file_paths[IDS] = join(dest_dir, f)
            if INVENTORY in f:
                self.src_image_file_paths[INVENTORY] = join(src_dir, f)
                self.dest_image_file_paths[INVENTORY] = join(dest_dir, f)
            if MM in f:
                self.src_image_file_paths[MM] = join(src_dir, f)
                self.dest_image_file_paths[MM] = join(dest_dir, f)
            if PAGEMAP in f:
                self.src_image_file_paths[PAGEMAP] = join(src_dir, f)
                self.dest_image_file_paths[PAGEMAP] = join(dest_dir, f)
            if PSTREE in f:
                self.src_image_file_paths[PSTREE] = join(src_dir, f)
                self.dest_image_file_paths[PSTREE] = join(dest_dir, f)
            if SECCOMP in f:
                self.src_image_file_paths[SECCOMP] = join(src_dir, f)
                self.dest_image_file_paths[SECCOMP] = join(dest_dir, f)
            if TIMENS in f:
                self.src_image_file_paths[TIMENS] = join(src_dir, f)
                self.dest_image_file_paths[TIMENS] = join(dest_dir, f)
            if TTYINFO in f:
                self.src_image_file_paths[TTYINFO] = join(src_dir, f)
                self.dest_image_file_paths[TTYINFO] = join(dest_dir, f)
            if PAGES in f:
                self.src_image_file_paths[PAGES] = join(src_dir, f)
                self.dest_image_file_paths[PAGES] = join(dest_dir, f)

    def log(self, *args):
        if(self.debug):
            print(args)
    
    def get_task_id(p, val):
        return p[val] if val in p else p['ns_' + val][0]

    def load_image_file(self, file_path, remove=False, fresh=False, pretty=True):
        if not fresh and file_path in self.images:
            if not remove:
                return self.images[file_path]
            else:
                img = self.images[file_path]
                del self.images[file_path]
                return img
        try:
            f = open(file_path, 'rb')
            img = pycriu.images.load(f, pretty=pretty)
            f.close()
            self.images[file_path] = img
            self.log('Loaded image file', file_path)
        except pycriu.images.MagicException as e:
            print("Error opening file", file_path)
            print(e)
            sys.exit(1)
        return img

    def dump_image_file(self, file_path, img):
        try:
            self.images[file_path] = img
            f = open(file_path, 'w+b')
            pycriu.images.dump(img, f)
            f.close()
            self.log('Dumped image file', file_path)
        except pycriu.images.MagicException as e:
            print('Error dumpig file', file_path)
            print(e)
            sys.exit(1)

    def get_all_pids(self, pstree_file):
        all_pids = list()
        pgm_img = self.load_image_file(pstree_file)
        for entry in pgm_img["entries"]:
            all_pids.append(entry["pid"])
        return all_pids

    def get_pages_id(self, pm_full_path):
        page_map = self.load_image_file(pm_full_path)
        return page_map["entries"][0]["pages_id"]

    def get_stack_page_offset(self, pm_full_path, sp):
        pages_to_skip = 0
        st_vaddr = 0
        end_vaddr = 0
        page_map = self.load_image_file(pm_full_path, False, True, False)
        for pm in page_map['entries'][1:]:
            nr_pages = pm['nr_pages']
            st_vaddr = pm['vaddr']
            end_vaddr = st_vaddr + (nr_pages << 12)
            if(sp > end_vaddr):
                pages_to_skip += nr_pages
                continue
            else:
                break
        assert pages_to_skip != 0 and st_vaddr != 0 and end_vaddr != 0, \
            "something went wrong computing stack offset"
        stack_page_offset = (pages_to_skip << 12) + (sp - st_vaddr)
        stack_base_offset = (pages_to_skip << 12) + (end_vaddr - st_vaddr)
        self.log('Stack Offset: ', stack_page_offset)
        return (stack_page_offset, stack_base_offset)
    
    def get_code_pages_offset(self, mm_img, pm_img):
        for vma in mm_img["entries"][0]["vmas"]:
            if 'PROT_EXEC' not in vma['prot']:
                continue
            if 'VMA_AREA_VSYSCALL' in vma['status']:
                continue
            if 'VMA_AREA_VDSO' in vma['status']:
                continue
            start_vaddr = vma['start']
            end_vaddr = vma['end']
            break
        assert start_vaddr, "Code page start address not found"
        assert end_vaddr, "Code page end address not found"
        ans = []
        pages_to_skip = 0
        num_pages = 0
        for p in pm_img['entries'][1:]:
            if int(p['vaddr'], 16) >= int(start_vaddr, 16) and int(p['vaddr'], 16) <= int(end_vaddr, 16):
                num_pages = p['nr_pages']
                code_offset = pages_to_skip << 12
                pages_to_skip += num_pages
                ans.append((code_offset, num_pages, p['vaddr']))
            else:
                pages_to_skip += p['nr_pages']
        assert ans, "Code pages not found"
        return ans
    
    def copy_code_pages(self, code_offset, num_pages, vaddr, text_start, dest_pages):
        dest_pages.seek(code_offset)
        (d, b) = self.get_dest_bin_path()
        dest = elf_utils.open_elf_file_fp(join(d, b))
        text = elf_utils.get_elf_section(dest, '.text')
        buffer = text.data()
        va = int(vaddr, 16)
        assert va >= text_start, "Probable logical error in getting vaddr"
        offset = va - text_start
        for i in range((num_pages << 12)//8):
            dest_pages.write(buffer[offset + i*8 : i*8 + 8 + offset])

    def get_exec_file_id(self, mm_file):
        mm_img = self.load_image_file(mm_file)
        return mm_img["entries"][0]["exe_file_id"]

    def get_binary_info(self, files_path, mm_file):
        files_img = self.load_image_file(files_path)
        fid = self.get_exec_file_id(mm_file)
        index = 0
        for entry in files_img["entries"]:
            if entry["id"] == fid:
                return fid, index
            index += 1
        return -1, -1

    def remove_region_type(self, mm_img, pagemap_img, page_tmp, original_size, region_type):
        region_start=-1
        region_end=-1
        #get address and remove vma
        idx=0
        for vma in mm_img["entries"][0]["vmas"][:]:
            if region_type in vma["status"]:
                region_start=int(vma["start"], 16)
                region_end=int(vma["end"], 16)
                self.log("removing vma",mm_img["entries"][0]["vmas"][idx])
                del mm_img["entries"][0]["vmas"][idx]
                break
            idx+=1
            
        if region_start==-1:
            print("no region found", region_type)
            return -1
            
        self.log(hex(region_start), hex(region_end))
        
        #pagemap
        idx=0
        found=False
        page_offset=-1
        page_start_nbr=0
        page_nbr=-1
        for pgmap in pagemap_img["entries"][:]:
            if "vaddr" not in pgmap.keys():
                idx+=1
                continue
            addr=int(pgmap["vaddr"], 16)
            page_nbr = pgmap['nr_pages']
            if addr >= region_start and addr <= region_end:
                found=True
                self.log("removing pagemap", pagemap_img["entries"][idx])
                del pagemap_img["entries"][idx]
                break
            idx+=1
            page_start_nbr+=page_nbr
        assert(page_nbr!=-1)
        
        new_size=original_size
        if(found):
            page_offset=page_start_nbr*PAGESIZE
            cnt_size=(page_nbr*PAGESIZE)
            page_offset_end=page_offset+cnt_size

            ###page_tmp=open(pages_path, "r+b")

            #content to be returned
            page_tmp.seek(page_offset)
            ret_cnt=page_tmp.read(cnt_size)

            ##truncate page_tmp from page_offset to page_offset_end
            #read the end of file
            page_tmp.seek(page_offset_end)
            buff=page_tmp.read(original_size-page_offset_end)

            #write the end of file starting at the moved region
            page_tmp.seek(page_offset)
            page_tmp.write(buff)

            #truncate file
            new_size=original_size-(page_offset_end-page_offset)
            self.log(original_size, new_size)
            page_tmp.truncate(new_size)
            ###page_tmp.close()

        return new_size
    
    def __add_target_region(self, mm_img, pagemap_img, page_tmp, original_size, mm_tmpl, pgmap_tmpl, cnt_tmpl):
        self.log("adding", mm_tmpl)

        #insert_vma
        region_start=int(mm_tmpl["start"], 16)
        region_end=int(mm_tmpl["end"], 16)
        vmas=mm_img["entries"][0]["vmas"]
        idx=0
        for vma in vmas:
            vma_start=int(vma["start"], 16)
            vma_end=int(vma["end"], 16)
            if vma_start >= region_end:
                #we need to insert before this region
                #check that we don't overlap with prev
                if(idx>0):
                    prev_vma=mm_img["entries"][0]["vmas"][idx-1]
                    pvend=int(prev_vma["end"],16)
                    if(pvend > region_start):
                        self.log("error: could not insert region", hex(vma_start), hex(vma_end), hex(region_start), hex(region_end), hex(pvend))
                        return -1
                break
            idx+=1
        self.log("found vma at idx", idx, len(vmas))
        mm_img["entries"][0]["vmas"]=vmas[:idx]+[mm_tmpl]+vmas[idx:]

        #insert pgmap if any (not an error)
        if not pgmap_tmpl:
            return original_size

        #pagemap
        idx=0
        page_offset=-1
        page_start_nbr=0
        page_nbr=-1
        target_vaddr=int(pgmap_tmpl["vaddr"], 16)
        target_nbr=pgmap_tmpl["nr_pages"]
        pages_list=pagemap_img["entries"]
        for pgmap in pages_list:
            #FIXME: handle case first entry
            if "vaddr" not in pgmap.keys():
                idx+=1
                continue
            addr=int(pgmap["vaddr"], 16)
            page_nbr = pgmap['nr_pages']
            addr_end=addr+(page_nbr*PAGESIZE)
            if addr >= target_vaddr:
                self.log("pagemap found spot")
                #insert before this regions
                break
            idx+=1
            page_start_nbr+=page_nbr
        self.log("found page at idx", idx, len(pages_list))
        self.log("found page at idx", pgmap_tmpl , pages_list[idx:])
        assert(page_nbr!=-1)
        pagemap_img["entries"]=pages_list[:idx]+[pgmap_tmpl]+pages_list[idx:]

        #where to insert in pages
        page_offset=page_start_nbr*PAGESIZE
        buff_size=(target_nbr*PAGESIZE)

        #insert in pages
        page_tmp.seek(page_offset)
        buff=page_tmp.read(original_size-page_offset)
        
        page_tmp.seek(page_offset)
        self.log(buff_size, len(cnt_tmpl))
        assert(buff_size == len(cnt_tmpl))
        page_tmp.write(cnt_tmpl)#, buff_size)
        page_tmp.write(buff) #, original_size-page_offset_end)
        ###page_tmp.close()

        return (original_size + buff_size)

    def add_target_region(self, mm_img, pagemap_img, page_tmp, original_size, region_type):
        mm_tmpl, pgmap_tmpl, cnt_tmpl = self.get_target_template(region_type)
        return self.__add_target_region(mm_img, pagemap_img, page_tmp, original_size, mm_tmpl, pgmap_tmpl, cnt_tmpl)

    def get_target_template(self, region_type):
        if "VDSO" in region_type:
            return self.get_vdso_template()
        if "VVAR" in region_type:
            return self.get_vvar_template()
        if "VSYSCALL" in region_type:
            return self.get_vsyscall_template()

    @abstractmethod
    def copy_bin_files(self):
        pass
    
    @abstractmethod
    def get_dest_bin_path(self):
        pass

    @abstractmethod
    def assert_conditions(self):
        pass

    def transform_cgroup_file(self):
        if CGROUP not in self.src_image_file_paths:
            return
        src_cgroup = self.src_image_file_paths[CGROUP]
        dst_cgroup = self.dest_image_file_paths[CGROUP]
        shutil.copyfile(src_cgroup, dst_cgroup)
        self.log('Copied cgroup file')

    def transform_fdinfo_file(self):
        if FDINFO not in self.src_image_file_paths:
            return
        src_fd = self.src_image_file_paths[FDINFO]
        dst_fd = self.dest_image_file_paths[FDINFO]
        shutil.copyfile(src_fd, dst_fd)
        self.log('Copied fdinfo file')

    def transform_fs_file(self):
        if FS not in self.src_image_file_paths:
            return
        src_fs = self.src_image_file_paths[FS]
        dst_fs = self.dest_image_file_paths[FS]
        shutil.copyfile(src_fs, dst_fs)
        self.log('Copied fs file')

    def transform_inventory_file(self):
        if INVENTORY not in self.src_image_file_paths:
            return
        src_inventory = self.src_image_file_paths[INVENTORY]
        dst_inventory = self.dest_image_file_paths[INVENTORY]
        shutil.copyfile(src_inventory, dst_inventory)
        self.log('Copied inventory file')

    def transform_pstree_file(self):
        if PSTREE not in self.src_image_file_paths:
            return
        src_ps = self.src_image_file_paths[PSTREE]
        dst_ps = self.dest_image_file_paths[PSTREE]
        shutil.copyfile(src_ps, dst_ps)
        self.log('Copied pstree file')

    def transform_ttyinfo_file(self):
        if TTYINFO not in self.src_image_file_paths:
            return
        src_tty = self.src_image_file_paths[TTYINFO]
        dst_tty = self.dest_image_file_paths[TTYINFO]
        shutil.copyfile(src_tty, dst_tty)
        self.log('Copied tty-info file')

    @abstractmethod
    def transform_core_file(self):  # core file template
        pass

    def transform_files_file(self):
        assert FILES in self.src_image_file_paths, "src files.img path not found"
        assert MM in self.src_image_file_paths, 'src mm img path not found'
        assert FILES in self.dest_image_file_paths, "dest files.img path not found"
        assert MM in self.dest_image_file_paths, 'dest mm img path not found'
        src_files_img = self.load_image_file(self.src_image_file_paths[FILES])
        (fid, idx) = self.get_binary_info(self.src_image_file_paths[FILES],
                                          self.src_image_file_paths[MM])
        (d, b) = self.get_dest_bin_path()
        bin = join(d, b)
        assert os.path.isfile(bin)
        stat = os.stat(bin)
        dst_files_img = copy(src_files_img)
        dst_files_img['entries'][idx]['reg']['size'] = stat.st_size
        self.dump_image_file(self.dest_image_file_paths[FILES], dst_files_img)
        self.log('Files image transformed')

    def transform_ids_file(self):
        if IDS not in self.src_image_file_paths:
            return
        src_ids = self.src_image_file_paths[IDS]
        dst_ids = self.dest_image_file_paths[IDS]
        shutil.copyfile(src_ids, dst_ids)
        self.log('Copied ids file')

    def transform_target_mem(self): ##mm, pagemap, pages for vdso, vvar, code_pages and vsyscall
        assert MM in self.src_image_file_paths, 'src mm img path not found'
        assert PAGEMAP in self.src_image_file_paths, 'src pagemap img path not found'
        assert PAGES in self.src_image_file_paths, 'src pages img path not found'
        assert MM in self.dest_image_file_paths, 'dest mm img path not found'
        assert PAGEMAP in self.dest_image_file_paths, 'dest pagemap img path not found'
        assert PAGES in self.dest_image_file_paths, 'dest pages img path not found'

        src_mm_img = self.load_image_file(self.src_image_file_paths[MM])
        src_pm_img = self.load_image_file(self.src_image_file_paths[PAGEMAP])

        dest_mm_img = copy(src_mm_img)
        dest_pm_img = copy(src_pm_img)
        
        (d, b) = self.get_dest_bin_path()
        dest_bin = elf_utils.open_elf_file(d, b)
        text_sec = elf_utils.get_elf_section(dest_bin, '.text')
        text_start = text_sec.header.sh_addr
        pg_off = text_sec.header.sh_offset
        text_end = align(text_start + text_sec.header.sh_size)
        vma = [v for v in dest_mm_img['entries'][0]['vmas'] \
            if 'PROT_EXEC' in v['prot'] and 'VMA_AREA_VDSO' not in v['status']][0]
        vma['start'] = hex(text_start)
        vma['end'] = hex(text_end)
        vma['pgoff'] = pg_off

        shutil.copyfile(self.src_image_file_paths[PAGES], self.dest_image_file_paths[PAGES])
        orig_size = os.stat(self.dest_image_file_paths[PAGES]).st_size
        dest_pages = open(self.dest_image_file_paths[PAGES], 'r+b')

        ret_size = self.remove_region_type(dest_mm_img, dest_pm_img, dest_pages, orig_size, "VDSO")
        if ret_size > 0:
            ret_size = self.add_target_region(dest_mm_img, dest_pm_img, dest_pages, orig_size, "VDSO")
            if ret_size > 0:
                orig_size = ret_size

        ret_size = self.remove_region_type(dest_mm_img, dest_pm_img, dest_pages, orig_size, "VVAR")
        if ret_size > 0:
            ret_size = self.add_target_region(dest_mm_img, dest_pm_img, dest_pages, orig_size, "VVAR")
            if ret_size > 0:
                orig_size = ret_size
        
        if self.arch == AARCH64:
            ret_size = self.remove_region_type(dest_mm_img, dest_pm_img, 
                dest_pages, orig_size, "VSYSCALL")
        elif self.arch == X8664:
            ret_size = self.add_target_region(dest_mm_img, dest_pm_img, 
                dest_pages, orig_size, "VSYSCALL")
        
        ans = self.get_code_pages_offset(dest_mm_img, dest_pm_img)
        for a in ans:
            self.copy_code_pages(a[0], a[1], a[2], text_start, dest_pages)
        dest_pages.close()

        self.dump_image_file(self.dest_image_file_paths[MM], dest_mm_img)
        self.dump_image_file(self.dest_image_file_paths[PAGEMAP], dest_pm_img)
        self.log('pagemap image file transformed')
        self.log('mm image file transformed')

    @abstractmethod
    def get_vdso_template(self):
        pass

    @abstractmethod
    def get_vvar_template(self):
        pass

    @abstractmethod
    def get_vsyscall_template(self):
        pass

    def transform_seccomp_file(self):
        if SECCOMP not in self.src_image_file_paths:
            return
        src_seccomp = self.src_image_file_paths[SECCOMP]
        dst_seccomp = self.dest_image_file_paths[SECCOMP]
        shutil.copyfile(src_seccomp, dst_seccomp)
        self.log('Copied seccomp file')

    def transform_timens_file(self):
        if TIMENS not in self.src_image_file_paths:
            return
        src_timens = self.src_image_file_paths[TIMENS]
        dst_timens = self.dest_image_file_paths[TIMENS]
        shutil.copyfile(src_timens, dst_timens)
        self.log('Copied timens file')

    def transform_stack_and_regs(self): # call after transform_core_file
        src_core = self.load_image_file(self.src_image_file_paths[CORE], False, True, False)
        dest_core = self.load_image_file(self.dest_image_file_paths[CORE], False, True, False)
        src_bin = elf_utils.open_elf_file(self.src_dir, self.bin)
        (d, b) = self.get_dest_bin_path()
        dest_bin = elf_utils.open_elf_file(d, b)
        
        if self.arch == AARCH64:
            src_handle = StHandle(definitions.X86_64, src_bin)
            dest_handle = StHandle(definitions.AARCH64, dest_bin)
        
            src_regset = reg_x86_64.RegsetX8664(src_core['entries'][self.entry_num])
            dest_regset = reg_aarch64.RegsetAarch64(dest_core['entries'][self.entry_num])
        
        elif self.arch == X8664:
            dest_handle = StHandle(definitions.X86_64, dest_bin)
            src_handle = StHandle(definitions.AARCH64, src_bin)
        
            dest_regset = reg_x86_64.RegsetX8664(dest_core['entries'][self.entry_num])
            src_regset = reg_aarch64.RegsetAarch64(src_core['entries'][self.entry_num])
        
        else:
            raise Exception("Architecture not supported")
        
        self.rewrite_context_init(src_handle, src_regset, dest_handle, dest_regset)
        assert self.dest_rewrite_ctx, 'dest rewrite context not initialized'
        assert self.src_rewrite_ctx, 'src rewrite context not initialized'
        unwind_and_size(self.src_rewrite_ctx, self.dest_rewrite_ctx)
        assert len(self.src_rewrite_ctx.activations) == \
            len(self.dest_rewrite_ctx.activations), "act count unequal for src and dest"
        for i in range(len(self.dest_rewrite_ctx.activations)):
            self.src_rewrite_ctx.act = i
            self.dest_rewrite_ctx.act = i
            rewrite_frame(self.src_rewrite_ctx, self.dest_rewrite_ctx)
        self.dest_rewrite_ctx.pages.close()
        self.dest_rewrite_ctx.regset = self.dest_rewrite_ctx.activations[0].regset
        self.dest_rewrite_ctx.regset.copy_out(dest_core['entries'][0])
        self.dump_image_file(self.dest_image_file_paths[CORE], dest_core)

    def rewrite_context_init(self, src_handle, src_regset, dest_handle, dest_regset):
        src_sp = src_handle.regops['sp'](src_regset)
        dest_sp = src_sp
        src_pm = self.src_image_file_paths[PAGEMAP]
        dest_pm = self.dest_image_file_paths[PAGEMAP]
        src_pages = open(self.src_image_file_paths[PAGES], 'rb')
        dest_pages = open(self.dest_image_file_paths[PAGES], 'r+b')
        (src_st_top_offset, src_st_base_offset) = \
            self.get_stack_page_offset(src_pm, src_sp)
        (dest_st_top_offset, dest_st_base_offset) = \
            self.get_stack_page_offset(dest_pm, dest_sp)
        src_rewrite_ctx = RewriteContext(src_handle, src_regset, 
            src_st_top_offset, src_st_base_offset, src_pages)
        self.src_rewrite_ctx = src_rewrite_ctx
        dest_rewrite_ctx = RewriteContext(dest_handle, dest_regset, 
            dest_st_top_offset, dest_st_base_offset, dest_pages)
        self.dest_rewrite_ctx = dest_rewrite_ctx

    def recode(self):
        if os.path.exists(self.dest_dir):
            shutil.rmtree(self.dest_dir)
        os.makedirs(self.dest_dir)
        #self.copy_bin_files()
        self.transform_cgroup_file()
        self.transform_fdinfo_file()
        self.transform_fs_file()
        self.transform_inventory_file()
        self.transform_pstree_file()
        self.transform_ttyinfo_file()
        self.transform_target_mem()
        self.transform_core_file()
        self.transform_files_file()
        self.transform_ids_file()
        self.transform_stack_and_regs()
        self.transform_seccomp_file()
        self.transform_timens_file()

#aarch64 to x86-64
class X8664Converter(Converter):
    def __init__(self, src_dir, dest_dir, src_bin, bin_dir, debug):
        Converter.__init__(self, src_dir, dest_dir, src_bin, bin_dir, debug)
        self.arch = X8664
    
    def assert_conditions(self):  # call before calling recode
        core_file = self.load_image_file(self.src_image_file_paths[CORE])
        entry = self.entry_num
        arch = core_file['entries'][entry]['mtype']
        x64_bin = join(self.bin_dir, self.bin+X8664_SUFFIX)
        base = join(self.src_dir, self.bin)
        a_stat = os.stat(x64_bin)
        b_stat = os.stat(base)
        #assert a_stat.st_mode == b_stat.st_mode, 'rwx modes do not match for src and dest bin'
        assert arch != X8664, "Same src and dest arch do not need transformation"
    
    def copy_bin_files(self):
        x64_bin = join(self.bin_dir, self.bin+X8664_SUFFIX)
        base = join(self.dest_dir, self.bin)
        shutil.copyfile(x64_bin, base)
        self.log('Binary copied')
    
    def get_dest_bin_path(self):
        x64_bin = self.bin+X8664_SUFFIX
        return (self.bin_dir, x64_bin)
    
    def get_vsyscall_template(self):
        mm={
            "start": "0xffffffffff600000", 
            "end": "0xffffffffff601000", 
            "pgoff": 0, 
            "shmid": 0, 
            "prot": "PROT_EXEC", 
            "flags": "MAP_PRIVATE | MAP_ANON", 
            "status": "VMA_AREA_VSYSCALL | VMA_ANON_PRIVATE", 
            "fd": -1
        }
        return mm, None, None
    
    def get_vvar_template(self):
        mm={
            "start": "0x7ffff7ffb000", 
            "end": "0x7ffff7ffe000",
            "pgoff": 0, 
            "shmid": 0, 
            "prot": "PROT_READ", 
            "flags": "MAP_PRIVATE | MAP_ANON", 
            "status": "VMA_AREA_REGULAR | VMA_ANON_PRIVATE | VMA_AREA_VVAR", 
            "fd": -1, 
            "madv": "0x10000"
        }
        return mm, None, None
    
    def get_vdso_template(self):
        mm= {
            "start": "0x7ffff7ffe000",
            "end": "0x7ffff7fff000",
            "pgoff": 0, 
            "shmid": 0, 
            "prot": "PROT_READ | PROT_EXEC", 
            "flags": "MAP_PRIVATE | MAP_ANON", 
            "status": "VMA_AREA_REGULAR | VMA_AREA_VDSO | VMA_ANON_PRIVATE", 
            "fd": -1
        }
        pgmap= { "vaddr": "0x7ffff7ffe000", "nr_pages": 1, "flags": "PE_PRESENT"}

        dir_path=os.path.dirname(os.path.realpath(__file__))
        vdso_path=os.path.join(dir_path, "templates/", "x86_64_vdso.img.tmpl")

        self.log("vdso path", vdso_path)
        f=open(vdso_path, "rb")
        vdso=f.read(PAGESIZE)
        f.close()
        return mm, pgmap, vdso
    
    def transform_core_file(self):
        assert CORE in self.src_image_file_paths, 'src core image file path not found'
        assert CORE in self.dest_image_file_paths, 'dest core image file path not found'
        src_core = self.load_image_file(self.src_image_file_paths[CORE])
        dest_core = copy(src_core)
        dest_regs = X86Struct()
        
        # Convert the type
        dest_core['entries'][self.entry_num]['mtype']="X86_64"

        # Convert thread info
        src_info=dest_core['entries'][self.entry_num]['ti_aarch64']
        dst_info=OrderedDict()
        tid_addr = int(src_info["clear_tid_addr"], 16)
        dst_info["clear_tid_addr"] = hex(tid_addr)

        # gpregs
        reg_dict=OrderedDict()
        translate={"rbp":"bp", "rbx":"bx", "rax":"ax", "rcx":"cx", 
            "rdx":"dx", "rsi":"si", "rdi":"di", "rsp":"sp"}
        for grn in X86Struct.gregs:
            trgn=grn
            if grn in translate.keys():
                trgn=translate[grn]
            reg_dict[trgn]=getattr(dest_regs, grn)
        reg_dict["ip"]=dest_regs.rip
        reg_dict["flags"] = hex(0x202) #0x206 or 0x202?
        reg_dict["orig_ax"] = hex(0xffffffffffffffff) #FIXME: to check
        reg_dict["fs_base"]=hex(src_info["tls"] - 272)
        self.log("fs_base", reg_dict["fs_base"])
        reg_dict["gs_base"]="0x0"

        # csregs
        for grn in X86Struct.csregs:
            trgn=grn
            if grn in translate.keys():
                trgn=translate[grn]
            reg_dict[trgn]=getattr(dest_regs, grn)
        reg_dict["ss"]="0x2b"
        reg_dict["cs"]="0x33"
        reg_dict["mode"]="NATIVE"
        self.log(reg_dict)
        dst_info["gpregs"]=reg_dict

        # fpregs
        self.log("WARNING: floating point registers not fully supported")
        dst_info["fpregs"]= {
            "cwd": 0, "swd": 0, "twd": 0, "fop": 0,
            "rip": 0, "rdp": 0, "mxcsr": 8064, "mxcsr_mask": 65535,
            "st_space": [ 0, 0, 0, 0, 0, 0, 0, 0,
						0, 0, 0, 0, 0, 0, 0, 0,
						0, 0, 0, 0, 0, 0, 0, 0,
						0, 2147483648, 16447, 0, 0, 2147483648, 16447, 0],
            "xmm_space": [0, 0, 0, 0, 3762528790, 1072013384, 0, 0,
						2696277389, 1051772663, 0, 0, 2405181686, 0, 20, 0, 
						0, 0, 0, 0, 0, 0, 0, 0,
						0, 0, 0, 0, 0, 0, 0, 0,
						0, 0, 0, 0, 0, 0, 0, 0,
						0, 0, 0, 0, 0, 0, 0, 0,
						0, 0, 0, 0, 0, 0, 0, 0, 
						0, 0, 0, 0, 0, 0, 0, 0], 
            "xsave": { "xstate_bv": 3,
                        "ymmh_space": [0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0],
                        "bndcsr_state": [0, 0, 0, 0, 0, 0, 0, 0] 
                    }
        }

        # TLS
        dst_info["tls"]=[
                    {
                    "entry_number": 12, 
                    "base_addr": 0, 
                    "limit": 0, 
                    "seg_32bit": False, 
                    "contents_h": False, 
                    "contents_l": False, 
                    "read_exec_only": True, 
                    "limit_in_pages": False, 
                    "seg_not_present": True, 
                    "useable": False
                    }, 
                    {
                    "entry_number": 13, 
                    "base_addr": 0, 
                    "limit": 0, 
                    "seg_32bit": False, 
                    "contents_h": False, 
                    "contents_l": False, 
                    "read_exec_only": True, 
                    "limit_in_pages": False, 
                    "seg_not_present": True, 
                    "useable": False
                    }, 
                    {
                    "entry_number": 14, 
                    "base_addr": 0, 
                    "limit": 0, 
                    "seg_32bit": False, 
                    "contents_h": False, 
                    "contents_l": False, 
                    "read_exec_only": True, 
                    "limit_in_pages": False, 
                    "seg_not_present": True, 
                    "useable": False
                    }
        ]

        # delete old entry and add the new one
        del dest_core['entries'][0]['ti_aarch64'] 
        ordered_dict_prepend(dest_core['entries'][0], 'thread_info', dst_info)
        ordered_dict_prepend(dest_core['entries'][0], 'mtype', "X86_64")

        self.dump_image_file(self.dest_image_file_paths[CORE], dest_core)
        self.log('Core file template created')


#x86-64 to aarch64
class Aarch64Converter(Converter):
    def __init__(self, src_dir, dest_dir, src_bin, bin_dir, debug):
        Converter.__init__(self, src_dir, dest_dir, src_bin, bin_dir, debug)
        self.arch = AARCH64

    def assert_conditions(self):  # call before calling recode
        core_file = self.load_image_file(self.src_image_file_paths[CORE])
        entry = self.entry_num
        arch = core_file['entries'][entry]['mtype']
        aarch64_bin = join(self.bin_dir, self.bin+AARCH64_SUFFIX)
        base = join(self.src_dir, self.bin)
        a_stat = os.stat(aarch64_bin)
        b_stat = os.stat(base)
        assert a_stat.st_mode == b_stat.st_mode, 'rwx modes do not match for src and dest bin'
        assert arch != AARCH64, "Same src and dest arch do not need transformation"

    def copy_bin_files(self):
        aarch64_bin = join(self.bin_dir, self.bin+AARCH64_SUFFIX)
        base = join(self.dest_dir, self.bin)
        shutil.copyfile(aarch64_bin, base)
        self.log('Binary copied')
    
    def get_dest_bin_path(self):
        aarch64_bin = self.bin+AARCH64_SUFFIX
        return (self.bin_dir, aarch64_bin)

    def get_vsyscall_template(self):
        return None, None, None

    def get_vvar_template(self):
        mm = {
            "start": "0xffffacaa5000",
            "end": "0xffffacaa6000",
            "pgoff": 0,
            "shmid": 0,
            "prot": "PROT_READ",
            "flags": "MAP_PRIVATE | MAP_ANON",
            "status": "VMA_AREA_REGULAR | VMA_ANON_PRIVATE | VMA_AREA_VVAR",
            "fd": -1
        }

        # TODO where is pgmap= ?
        return mm, None, None

    def get_vdso_template(self):
        mm = {
            "start": "0xffffacaa6000",
            "end": "0xffffacaa7000",
            "pgoff": 0,
            "shmid": 0,
            "prot": "PROT_READ | PROT_EXEC",
            "flags": "MAP_PRIVATE | MAP_ANON",
            "status": "VMA_AREA_REGULAR | VMA_AREA_VDSO | VMA_ANON_PRIVATE",
            "fd": -1
        }
        pgmap = {
            "vaddr": "0xffffacaa6000",
            "nr_pages": 1,
            "flags": "PE_PRESENT"
        }
        dir_path = os.path.dirname(os.path.realpath(__file__))
        vdso_path = os.path.join(
            dir_path, "templates/", "aarch64_vdso.img.tmpl")
        f = open(vdso_path, "rb")
        vdso = f.read(PAGESIZE)
        f.close()
        return mm, pgmap, vdso

    def transform_core_file(self):
        assert CORE in self.src_image_file_paths, 'src core image file path not found'
        assert CORE in self.dest_image_file_paths, 'dest core image file path not found'
        src_core = self.load_image_file(self.src_image_file_paths[CORE])
        dest_core = copy(src_core)
        dest_tls = int(src_core['entries'][0]['thread_info']['gpregs']['fs_base'], 16) + 272
        dest_regs = Aarch64Struct()

        #type conversion
        dest_core['entries'][0]['mtype']="AARCH64"

        #convert thread_info
        src_info=dest_core['entries'][0]['thread_info']
        dst_info=OrderedDict() 
        dst_info["clear_tid_addr"]=src_info["clear_tid_addr"]
        dst_info["tls"]=dest_tls

        #gpregs
        dst_info["gpregs"]=OrderedDict()
        #regs
        reg_list=list()
        for reg in dest_regs.regs:
            reg_list.append(hex(reg.x).rstrip('L'))
        dst_info["gpregs"]["regs"]=reg_list
        #sp, pc, pstate
        dst_info["gpregs"]["sp"]=dest_regs.sp
        dst_info["gpregs"]["pc"]=dest_regs.pc
        dst_info["gpregs"]["pstate"]="0x60000000" #?
        #fpsimd
        dst_info["fpsimd"]=OrderedDict()
        vreg_list=list()
        for vreg in dest_regs.vregs:
            #FIXME:check order
            vreg_list.append(hex(vreg.x).rstrip('L'))
            vreg_list.append(hex(vreg.y).rstrip('L'))
        dst_info["fpsimd"]["vregs"]=vreg_list
        dst_info["fpsimd"]["fpsr"]=0 #?
        dst_info["fpsimd"]["fpcr"]=0 #?

        #delete old entry and add the new one
        del dest_core['entries'][0]['thread_info']
        dest_core['entries'][0]['ti_aarch64'] = dst_info
        self.dump_image_file(self.dest_image_file_paths[CORE], dest_core)
        self.log('Core file template created')
