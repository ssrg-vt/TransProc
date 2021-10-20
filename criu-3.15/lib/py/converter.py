# Current version by Abhishek Bapat, Virginia Tech 2021.

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

from typing import AbstractSet
import pycriu
import sys
import os
import shutil

from abc import ABCMeta, abstractmethod
from os import listdir
from os.path import isfile, join


class Converter():
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
        self.mult_entry_files = [
            'cgroup', 
            'core', 
            'fdinfo',
            'files', 
            'fs',
            'ids',
            'inventory',
            'mm',
            'pagemap',
            'pstree',
            'seccomp',
            'timens',
            'tty-info'
        ]
        self.stack_page_offset = -1
        self.src_image_file_names = dict()
        self.dest_image_file_names = dict()
        img_files = [f for f in listdir() if (isfile(join(src_dir, f)) and "img" in f)]
        for f in img_files:
            if CGROUP in f:
                self.src_image_file_names[CGROUP] = join(src_dir, f)
                self.dest_image_file_names[CGROUP] = join(dest_dir, f)
            if CORE in f:
                self.src_image_file_names[CORE] = join(src_dir, f)
                self.dest_image_file_names[CORE] = join(dest_dir, f)
            if FDINFO in f:
                self.src_image_file_names[FDINFO] = join(src_dir, f)
                self.dest_image_file_names[FDINFO] = join(dest_dir, f)
            if FILES in f:
                self.src_image_file_names[FILES] = join(src_dir, f)
                self.dest_image_file_names[FILES] = join(dest_dir, f)
            if FS in f:
                self.src_image_file_names[FS] = join(src_dir, f)
                self.dest_image_file_names[FS] = join(dest_dir, f)
            if IDS in f:
                self.src_image_file_names[IDS] = join(src_dir, f)
                self.dest_image_file_names[IDS] = join(dest_dir, f)
            if INVENTORY in f:
                self.src_image_file_names[INVENTORY] = join(src_dir, f)
                self.dest_image_file_names[INVENTORY] = join(dest_dir, f)
            if MM in f:
                self.src_image_file_names[MM] = join(src_dir, f)
                self.dest_image_file_names[MM] = join(dest_dir, f)
            if PAGEMAP in f:
                self.src_image_file_names[PAGEMAP] = join(src_dir, f)
                self.dest_image_file_names[PAGEMAP] = join(dest_dir, f)
            if PSTREE in f:
                self.src_image_file_names[PSTREE] = join(src_dir, f)
                self.dest_image_file_names[PSTREE] = join(dest_dir, f)
            if SECCOMP in f:
                self.src_image_file_names[SECCOMP] = join(src_dir, f)
                self.dest_image_file_names[SECCOMP] = join(dest_dir, f)
            if TIMENS in f:
                self.src_image_file_names[TIMENS] = join(src_dir, f)
                self.dest_image_file_names[TIMENS] = join(dest_dir, f)
            if TTYINFO in f:
                self.src_image_file_names[TTYINFO] = join(src_dir, f)
                self.dest_image_file_names[TTYINFO] = join(dest_dir, f)


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
    
    def get_pid(self, p, val):
        return p[val] if val in p else p['ns_' + val][0]
    
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
            "something went wrong reading stack"
        self.stack_page_offset = (pages_to_skip << 12) + (sp - st_vaddr)
        self.log('Stack Offset: ', self.stack_page_offset)
        return self.stack_page_offset
    
    @abstractmethod
    def copy_bin_files(self):
        pass

    @abstractmethod
    def transform_cgroup_file(self):
        pass

    @abstractmethod
    def transform_fdinfo_file(self):
        pass

    @abstractmethod
    def transform_fs_file(self):
        pass

    @abstractmethod
    def transform_inventory_file(self):
        pass

    @abstractmethod
    def transform_pagemap_file(self):
        pass

    @abstractmethod
    def transform_pstree_file(self):
        pass

    @abstractmethod
    def transform_ttyinfo_file(self):
        pass

    @abstractmethod
    def transform_core_file(self): #regs
        pass

    @abstractmethod
    def transform_files_file(self):
        pass

    @abstractmethod
    def transform_ids_file(self):
        pass

    @abstractmethod
    def transform_mm_file(self):
        pass

    @abstractmethod
    def transform_seccomp_file(self):
        pass

    @abstractmethod
    def transform_timens_file(self):
        pass

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
