# Current version by Abhishek Bapat. SSRG, Virginia Tech 2021.
# abapat28@vt.edu

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

import pycriu
import sys
import os
import shutil

from abc import ABCMeta, abstractmethod
from os import listdir
from os.path import isfile, join


class Converter(): #TODO: Extend the logic for multiple PIDs
    __metaclass__ = ABCMeta
    def __init__(self, src_dir, dest_dir, bin, debug):
        assert os.path.exists(src_dir), "Source directory does not exist"
        assert os.path.exists(join(src_dir, bin)), "Source binary does not exist"
        assert os.path.exists(join(src_dir, bin+'_x86-64')), "Binary x86-64 copy does not exist"
        assert os.path.exists(join(src_dir, bin+'_aarch64')), "Binary aarch64 copy does not exist"
        self.debug = debug
        self.images = {}
        self.src_dir = src_dir
        self.dest_dir = dest_dir
        self.bin = bin
        self.entry_num = 0
        self.files_per_pid = [
            IDS,
            MM,
            CORE,
            FS,
            PAGEMAP,
        ]
        self.stack_page_offset = -1
        self.src_image_file_paths = dict()
        self.dest_image_file_paths = dict()
        img_files = [f for f in listdir(src_dir) if (isfile(join(src_dir, f)) and "img" in f)]
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


    def log(self, *args):
        if(self.debug):
            print(args)
        
    def load_image_file(self, file_path, remove=False):
        if file_path in self.images:
            if not remove:
                return self.images[file_path]
            else:
                img = self.images[file_path]
                del self.images[file_path]
                return img
        try:
            f = open(file_path, 'rb')
            img = pycriu.images.load(f, pretty=True)
            f.close()
            self.images[file_path] = img
            self.log('Loaded image file', file_path)
        except pycriu.images.MagicException as e:
            print("Error opening file", file_path)
            print(e)
            sys.exit(1)
        return img
    
    def get_all_pids(self, pstree_file):
        all_pids=list()
        pgm_img=self.load_image_file(pstree_file)
        for entry in pgm_img["entries"]:
            all_pids.append(entry["pid"])
        return all_pids
    
    def get_pages_id(self, pm_full_path):
        page_map = self.load_image_file(pm_full_path)
        return page_map["entries"][0]["pages_id"]
    
    def get_stack_page_offset(self, pm_full_path, sp):
        if(self.stack_page_offset >= 0):
            return self.stack_page_offset
        pages_to_skip = 0
        st_vaddr = 0
        end_vaddr = 0
        page_map = self.load_image_file(pm_full_path)
        for pm in page_map[1:]:
            nr_pages = pm['nr_pages']
            end_vaddr = st_vaddr + (nr_pages << 12)
            if(sp > end_vaddr):
                pages_to_skip += nr_pages
                continue
            else:
                break
        assert pages_to_skip != 0 and st_vaddr != 0 and end_vaddr !=0, \
            "something went wrong computing stack offset"
        self.stack_page_offset = (pages_to_skip << 12) + (sp - st_vaddr)
        self.log('Stack Offset: ', self.stack_page_offset)
        return self.stack_page_offset
    
    @abstractmethod
    def copy_bin_files(self):
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

    @abstractmethod
    def transform_pagemap_file(self):
        pass

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
    def transform_core_file(self): #regs
        pass

    @abstractmethod
    def transform_files_file(self):
        pass

    def transform_ids_file(self):
        if IDS not in self.src_image_file_paths:
            return
        src_ids = self.src_image_file_paths[IDS]
        dst_ids = self.dest_image_file_paths[IDS]
        shutil.copyfile(src_ids, dst_ids)
        self.log('Copied ids file')

    @abstractmethod
    def transform_mm_file(self):
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

    @abstractmethod
    def transform_pages_file(self): #stack, code_pages, vdso
        pass

    def recode(self):
        if os.path.exists(self.dest_dir):
            shutil.rmtree(self.dest_dir)
        os.makedirs(self.dest_dir)
        self.copy_bin_files()
        self.transform_cgroup_file()
        self.transform_fdinfo_file()
        self.transform_fs_file()
        self.transform_inventory_file()
        self.transform_pagemap_file()
        self.transform_pstree_file()
        self.transform_ttyinfo_file()
        self.transform_core_file()
        self.transform_files_file()
        self.transform_ids_file()
        self.transform_mm_file()
        self.transform_pages_file()
        self.transform_seccomp_file()
        self.transform_timens_file()


class Aarch64Converter(Converter):
    def __init__(self, src_dir, dest_dir, bin, debug):
        Converter.__init__(self, src_dir, dest_dir, bin, debug)
        self.arch = AARCH64

    def assert_conditions(self): # call before calling recode
        core_file = self.load_image_file(self.src_image_file_paths[CORE])
        entry = self.entry_num
        arch = core_file['entries'][entry]['mtype']
        assert arch != AARCH64, "Same src and dest arch do not need transformation"
    
    def copy_bin_files(self):
        x86_bin = join(self.src_dir, self.bin+X8664_SUFFIX)
        aarch64_bin = join(self.src_dir, self.bin+AARCH64_SUFFIX)
        base = join(self.dest_dir, self.bin)
        x86_bin_cp = join(self.dest_dir, self.bin+X8664_SUFFIX)
        aarch64_bin_cp = join(self.dest_dir, self.bin+AARCH64_SUFFIX)
        shutil.copyfile(x86_bin, x86_bin_cp)
        shutil.copyfile(aarch64_bin, aarch64_bin_cp)
        shutil.copyfile(aarch64_bin, base)
        self.log('Binaries copied')
    