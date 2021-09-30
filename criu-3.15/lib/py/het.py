
# Original version by Mohmmed Karoi Lamine, Virginia Tech 2019
# Old version by Antonio Barbalace and Tong Xing, Stevens 2019
# Current version by Abhishek Bapat, Virginia Tech 2021

import os
import json
import sys
import pycriu
import copy
import shutil
import tempfile
import time
import subprocess

from os import close, listdir
from os.path import isfile, join
from collections import OrderedDict
from ctypes import *
from shutil import copyfile
from abc import ABCMeta, abstractmethod
from subprocess import Popen, PIPE
from pycriu.images import pb2dict

PAGE_SIZE=4096
ELF_binaries ={}
IMG_files ={}
binary_symbols ={}

long = int

def het_log(*args):
	pass 
	#print(args)

class Reg64(Structure):
	_fields_ = [("x", c_ulonglong)]
class Reg128(Structure):
	_fields_ = [("x", c_ulonglong), ("y", c_ulonglong)]
class Aarch64Struct(Structure):
	_fields_ = [("magic", c_ulonglong), ("sp", c_ulonglong), ("pc", c_ulonglong), ("regs", Reg64 * 31), ("vregs", Reg128 * 32)]
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

class Converter():
	__metaclass__ = ABCMeta
	def __init__(self):
		pass

	### Common
	def get_symbol_addr(self, binary, symbol):
		if len(binary_symbols) == 0:
			session = subprocess.Popen(['nm', binary], stdout=PIPE, stderr=PIPE)
			_stdout, _stderr = session.communicate()
			nm_symbols = _stdout.split(b'\n')
			for nm_symbol in nm_symbols:
				sentry = nm_symbol.split()
				if sentry is not None:
					if len(sentry) >2:
						binary_symbols[sentry[2]] = sentry[0]
		return long(binary_symbols[symbol], 16)

	def __get_symbol_addr(self, binary, symbol):
		###find address of the structure
		###use a cache to avoid reloading the same binary multiple times
		if binary in ELF_binaries:
			e = ELF_binaries[binary]
		else:
			e = ELF(binary)
			ELF_binaries[binary] = e
		
		addr=long(e.symbols[symbol]) 
		het_log("found address", hex(addr))
		return addr

	def load_image_file(self, file_path, remove = False):
		###use a cache to avoid reloading the same file multiple times
		if file_path in IMG_files:
			if not remove:
				return IMG_files[file_path]
			else:
				pgm_img = IMG_files[file_path]
				del IMG_files[file_path]
				return pgm_img
		
		try:
			f = open(file_path, 'rb')
			pgm_img = pycriu.images.load(f, pretty=True)
			f.close()
		except pycriu.images.MagicException as exc:
			print("Error reading", file_path)
			sys.exit(1)
		if not close:
			IMG_files[file_path] = pgm_img
		return pgm_img

	def get_pages_offset(self, addr, pagemap_file):
		###find the offset size of the structure in pages_file using pagemap_file
		#find offset, size? (168?)
		pgm_img=self.load_image_file(pagemap_file)
		page_number=0
		region_offset=-1
		for dc in  pgm_img['entries']:
			if 'vaddr' in dc.keys():
				base = long(dc['vaddr'], 16)
				pnbr = dc['nr_pages']
				end = base+(pnbr*PAGE_SIZE)
				het_log("current region", hex(base), hex(end), pnbr)
				if addr>=base and addr<end:
					region_offset=(addr-base)
					region_offset+=(page_number*PAGE_SIZE)
					het_log("found in region", hex(base), hex(addr), hex(end))
					het_log("page offset",  region_offset)
					break
				page_number+=pnbr

		return region_offset

	def read_struct_from_pages(self, pages_file, region_offset, struct_def):
		#read at correcpoding offset
		fd=open(pages_file, 'rb')
		fd.seek(region_offset)
		dest_regs = struct_def()

		#het_log "reading", fd.read(-1) 
		#return
		ret=fd.readinto(dest_regs) 
		het_log("size", sizeof(dest_regs), "ret", ret)
		het_log("magic", hex(dest_regs.magic))
		return dest_regs

	def read_llong_from_pages(self, pages_file, region_offset):
		#read at correcpoding offset
		fd=open(pages_file, 'rb')
		fd.seek(region_offset)
		dest_reg = Reg64()
		ret=fd.readinto(dest_reg) 
		return dest_reg.x


	# def read_regs_from_memory(self, binary, architecture, pagemap_file, pages_file, struct_def):
	# 	rrfm_time = time.time()
	# 	addr=self.get_symbol_addr(binary, b'regs_dst')
	# 	rrfm_time1 = time.time()

	# 	region_offset=self.get_pages_offset(addr, pagemap_file)
	# 	if(region_offset==-1):
	# 		print("rrfm: addr region not found", binary, architecture)
	# 		return
	# 	rrfm_time2 = time.time()
	# 	regs= self.read_struct_from_pages(pages_file, region_offset, struct_def)
	# 	rrfm_time3 = time.time()
		
	# 	het_log("rrfm", rrfm_time1 -rrfm_time, rrfm_time2 -rrfm_time1, rrfm_time3 -rrfm_time2)
	# 	return regs

	# def read_tls_from_memory(self, binary, architecture, pagemap_file, pages_file):
	# 	rrfm_time = time.time()
	# 	addr=self.get_symbol_addr(binary, b'tls_dst')
	# 	rrfm_time1 = time.time()

	# 	region_offset=self.get_pages_offset(addr, pagemap_file)
	# 	if(region_offset==-1):
	# 		rrfm_time2 = time.time()
	# 		print("rtfm: addr region not found", (rrfm_time1 - rrfm_time), (rrfm_time2 - rrfm_time1))
	# 		return
	# 	rrfm_time2 = time.time()
		
	# 	het_log("rtfm", rrfm_time -rrfm_time, rrfm_time2 -rrfm_time1)
	# 	tls_addr=self.read_llong_from_pages(pages_file, region_offset)
	# 	het_log("!!!!tls_base", hex(tls_addr))
	# 	return tls_addr


	def get_src_core(self, core_file):
		pgm_img=self.load_image_file(core_file)
		return pgm_img

	def get_exec_file_id(self, mm_file):
		pgm_img=self.load_image_file(mm_file)
		return pgm_img["entries"][0]["exe_file_id"]

	def get_binary_info(self, files_path, mm_file, path_append):
		pgm_img=self.load_image_file(files_path)
		fid=self.get_exec_file_id(mm_file)
		index=0
		for entry in pgm_img["entries"]:
			if entry["id"]==fid:
				return fid, index, path_append+entry["reg"]["name"]
			index+=1
		return -1, -1, None

	def get_binary(self, files_path, mm_file, path_append):
		fid, idx, path=self.get_binary_info(files_path, mm_file, path_append)
		het_log("path to file", path)
		return path

	def get_all_pids(self, pstree_file):
		all_pids=list()
		pgm_img=self.load_image_file(pstree_file)
		for entry in pgm_img["entries"]:
			all_pids.append(entry["pid"])
		return all_pids

	def get_pages_id(self, pagemap_file):
		pgm_img=self.load_image_file(pagemap_file)
		return pgm_img["entries"][0]["pages_id"]

	def get_tmp_copy(self, src_file):
		temp_dir = tempfile.gettempdir()
		temp_file = os.path.join(temp_dir, 'pages.tmp')
		shutil.copy(src_file, temp_file)
		return temp_file

	def remove_region_type(self, mm_img, pagemap_img, page_tmp, original_size, region_type):
		#return what has been removed
		ret_mm=None
		ret_pmap=None
		ret_cnt=None

		region_start=-1
		region_end=-1
		#get address and remove vma
		idx=0
		for vma in mm_img["entries"][0]["vmas"][:]:
			if region_type in vma["status"]:
				region_start=int(vma["start"], 16)
				region_end=int(vma["end"], 16)
				
				het_log("removing vma",mm_img["entries"][0]["vmas"][idx])
				ret_mm = copy.deepcopy(mm_img["entries"][0]["vmas"][idx])
				del mm_img["entries"][0]["vmas"][idx]
				break
			idx+=1

		if region_start==-1:
			print("no region found", region_type)
			return -1

		het_log(hex(region_start), hex(region_end))
		
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
				
				het_log("removing pagemap", pagemap_img["entries"][idx])
				ret_pmap = copy.deepcopy(pagemap_img["entries"][idx])
				del pagemap_img["entries"][idx]
				break
			idx+=1
			page_start_nbr+=page_nbr
		assert(page_nbr!=-1)
		
		new_size=original_size
		if(found):
			###original_size=os.stat(pages_path).st_size
			###het_log("orginal size", pages_path, original_size, page_nbr)
			page_offset=page_start_nbr*PAGE_SIZE
			cnt_size=(page_nbr*PAGE_SIZE)
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
			het_log(original_size, new_size)
			page_tmp.truncate(new_size)
			###page_tmp.close()

		###return ret_mm, ret_pmap, ret_cnt
		return new_size


	def __add_target_region(self, mm_img, pagemap_img, page_tmp, original_size, mm_tmpl, pgmap_tmpl, cnt_tmpl):
		het_log("adding", mm_tmpl)

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
						het_log("error: could not insert region", hex(vma_start), hex(vma_end), hex(region_start), hex(region_end), hex(pvend))
						return -1
				break
			idx+=1
		het_log("found vma at idx", idx, len(vmas))
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
			addr_end=addr+(page_nbr*PAGE_SIZE)
			if addr >= target_vaddr:
				het_log("pagemap found spot")
				#insert before this regions
				break
			idx+=1
			page_start_nbr+=page_nbr
		het_log("found page at idx", idx, len(pages_list))
		het_log("found page at idx", pgmap_tmpl , pages_list[idx:])
		assert(page_nbr!=-1)
		pagemap_img["entries"]=pages_list[:idx]+[pgmap_tmpl]+pages_list[idx:]

		#where to insert in pages
		###original_size=os.stat(pages_path).st_size
		page_offset=page_start_nbr*PAGE_SIZE#+(page_nbr*PAGE_SIZE)
		buff_size=(target_nbr*PAGE_SIZE)
		#het_log("orginal size", pages_path, original_size, target_nbr, page_offset)

		#insert in pages
		###page_tmp=open(pages_path, "r+b")
		page_tmp.seek(page_offset)
		buff=page_tmp.read(original_size-page_offset)
		
		page_tmp.seek(page_offset)
		het_log(buff_size, len(cnt_tmpl))
		assert(buff_size == len(cnt_tmpl))
		page_tmp.write(cnt_tmpl)#, buff_size)
		page_tmp.write(buff) #, original_size-page_offset_end)
		###page_tmp.close()

		return (original_size + buff_size)

	def add_target_region(self, mm_img, pagemap_img, page_tmp, original_size, region_type):
		mm_tmpl, pgmap_tmpl, cnt_tmpl = self.get_target_template(region_type)
		return self.__add_target_region(mm_img, pagemap_img, page_tmp, original_size, mm_tmpl, pgmap_tmpl, cnt_tmpl)

	@abstractmethod
	def get_vdso_template(self):
		pass

	@abstractmethod
	def get_vvar_template(self):
		pass

	@abstractmethod
	def get_vsyscall_template(self):
		pass

	def get_target_template(self, region_type):
		if "VDSO" in region_type:
			return self.get_vdso_template()
		if "VVAR" in region_type:
			return self.get_vvar_template()
		if "VSYSCALL" in region_type:
			return self.get_vsyscall_template()

	@abstractmethod
	def get_target_core(self, arch, binary, pages_file, pagemap_file, core_file):
		pass
	@abstractmethod
	def get_target_files(self, files_path, mm_file, path_append, root_dir):
		pass
	@abstractmethod
	def get_target_mem(self, mm_file, pagemap_file,  pages_file, dest_path):
		pass
	@abstractmethod
	def transform_files_img(self, files_img):
		pass
	@abstractmethod
	def transform_ttyinfo_img(self, tty_img):
		pass

	def __recode_pid(self, pid, arch, directory, outdir, onlyfiles, files_file, path_append, root_dir):
		time_start = time.time()
		### To convert we need some files #TODO: use magic to identify the files?
		#TODO: use dict!
		pagemap_file=""
		pages_file=""
		core_file=""
		mm_file=""
		for fl in onlyfiles:
			if str(pid) not in fl:
				continue
			if "pagemap" in fl:	
				pagemap_file=os.path.join(directory, fl)
			if "core" in fl:	
				core_file=os.path.join(directory, fl)
			if "mm" in  fl:
				mm_file=os.path.join(directory, fl)
		het_log(pagemap_file , core_file , files_file , mm_file)
		assert(pagemap_file and core_file and files_file and mm_file)
		pages_id=self.get_pages_id(pagemap_file)
		for fl in onlyfiles:
			if "pages-"+str(pages_id) in fl:
				pages_file=os.path.join(directory, fl)
		assert(pages_file)
		
		##get path to binary
		binary=self.get_binary(files_file, mm_file, path_append)
		tmp_root_dir = root_dir
		tmp_root_dir += binary
		binary = tmp_root_dir
		het_log("path to binary", binary, path_append)
		time_path = time.time()
		
		#convert core, fs, memory (vdso)
		dest_core=self.get_target_core(arch, binary, pages_file, pagemap_file, core_file)
		time_core = time.time()
		dest_files=self.get_target_files(files_file, mm_file, path_append, root_dir) #must be after get_target_core
		time_files = time.time()

		bname=os.path.basename(pages_file)
		dst_file=os.path.join(outdir, bname)
		dest_mm, dest_pagemap, dest_pages_path=self.get_target_mem(mm_file, pagemap_file,  pages_file, dst_file)
		time_mem = time.time()

		handled_files=[]
		#populate with files TODO must handle pid (see above)
		for fl in onlyfiles:
			src_file=None
			if "core" in fl:
				src_file=core_file
				dest_img=dest_core
			if "mm" in fl:
				src_file=mm_file
				dest_img=dest_mm
			if "pagemap" in fl:
				src_file=pagemap_file
				dest_img=dest_pagemap
			if "files" in fl:
				src_file=files_file
				dest_img=dest_files
			if "pages" in fl:
				src_file=pages_file
				dest_img=dest_pages_path
			if not src_file:
				continue
			handled_files.append(src_file)
			bname=os.path.basename(src_file)
			dst_file=os.path.join(outdir, bname)
			if "pages" in fl: #just copy to target file
				het_log("copy of pages file (mem) already done above... we modified the final copy directly")
			else:
				het_log("src", dest_img, "dst", dst_file)
				pycriu.images.dump(dest_img, open(dst_file, "w+b"))
		time_copy = time.time()
		print (pid, (time_path - time_start), (time_core - time_path), (time_files - time_core), (time_mem - time_files), (time_copy - time_mem))
		return handled_files

	def recode(self, arch, directory, outdir, path_append, root_dir, serial):
		###Generate output directory
		if not os.path.exists(outdir):
			os.makedirs(outdir)
		rec_t0 =time.time()
		onlyfiles = [f for f in listdir(directory) if (isfile(join(directory, f)) and "img" in f)]
		pstree_file=None
		files_file=None
		handled_files=[]
		for fl in onlyfiles:
			if "pstree" in fl:	
				pstree_file=os.path.join(directory, fl)
			if "files" in  fl: #use the same file across recode_pid
				files_file_orig=os.path.join(directory, fl)
				handled_files.append(files_file_orig)
				bname=os.path.basename(files_file_orig)
				files_file=os.path.join(outdir, bname)
				copyfile(files_file_orig, files_file)
				if serial:
					self.transform_files_img(files_file)
			if "tty-info" in fl:
				if not serial:
					continue
				tty_orig=os.path.join(directory, fl)
				self.transform_ttyinfo_img(tty_orig)

		assert(pstree_file)
		assert(files_file)
		rec_t1 =time.time()
		for _pid in self.get_all_pids(pstree_file):
			ret=self.__recode_pid(_pid, arch, directory, outdir, onlyfiles, files_file, path_append,root_dir)
			handled_files.extend(ret)
		
		#copy not transformed files
		rec_t2 =time.time()
		het_log("copying remaining files")
		for fl in onlyfiles:
			het_log("copying...", fl)
			dst_file=os.path.join(outdir, fl)
			src_file=os.path.join(directory, fl)
			if src_file in handled_files:
				het_log("skipped", fl)
			else:
				#copy not transformed files:
				copyfile(src_file, dst_file)
				het_log("done", fl)
				
		rec_t3 =time.time()
		het_log("recode", (rec_t1 -rec_t0), (rec_t2 -rec_t1), (rec_t3 -rec_t2))

### FROM aarch64 TO x86_64
class X8664Converter(Converter):
	def __init__(self):
		Converter.__init__(self)
	
	def __get_rlimits(self):
		return [{"cur": 18446744073709551615, "max": 18446744073709551615}, 
			{"cur": 18446744073709551615, "max": 18446744073709551615}, 
			{"cur": 18446744073709551615, "max": 18446744073709551615}, 
			{"cur": 8388608, "max": 18446744073709551615}, {"cur": 0, "max": 18446744073709551615}, 
			{"cur": 18446744073709551615, "max": 18446744073709551615}, 
			{"cur": 515133, "max": 515133}, 
			{"cur": 8192, "max": 100000}, 
			{"cur": 65536, "max": 65536}, 
			{"cur": 18446744073709551615, "max": 18446744073709551615}, 
			{"cur": 18446744073709551615, "max": 18446744073709551615}, 
			{"cur": 515133, "max": 515133}, 
			{"cur": 819200, "max": 819200}, 
			{"cur": 0, "max": 0}, 
			{"cur": 0, "max": 0}, 
			{"cur": 18446744073709551615, "max": 18446744073709551615}]

	def convert_to_dest_core(self, pgm_img, dest_regs, dest_tls): #, old_stack_tmpl, new_stack_tmpl):
		het_log("Magic", dest_regs.magic) #TODO: check

		###convert the type
		pgm_img['entries'][0]['mtype']="X86_64"

		###convert thread_info
		src_info=pgm_img['entries'][0]['ti_aarch64']
		dst_info=OrderedDict() 
		#copy clear_tid_addr
		dst_info["clear_tid_addr"]=src_info["clear_tid_addr"]
		#Gpregs
		reg_dict=OrderedDict()
		translate={"rbp":"bp", "rbx":"bx", "rax":"ax", "rcx":"cx", "rdx":"dx", "rsi":"si", "rdi":"di", "rsp":"sp"}
		for grn in X86Struct.gregs:
			trgn=grn
			if grn in translate.keys():
				trgn=translate[grn]
			reg_dict[trgn]=getattr(dest_regs, grn)
		reg_dict["ip"]=dest_regs.rip
		reg_dict["flags"]=dest_regs.rflags #0x206 or 0x202?
		reg_dict["orig_ax"]=dest_regs.rax #FIXME: to check
		#reg_dict["fs_base"]=hex(dest_tls) #"0x821460" #FIXME!!!
		reg_dict["fs_base"]=hex(int(src_info["clear_tid_addr"],16)-56)#"0x821460" #FIXME!!!
		het_log("fs_base", reg_dict["fs_base"])
		reg_dict["gs_base"]="0x0"

		#csregs
		#translate={"rbp":"bp", "rbx":"bx", "rax":"ax", "rcx":"cx", "rdx":"dx", "rsi":"si", "rdi":"di"}
		for grn in X86Struct.csregs:
			trgn=grn
			if grn in translate.keys():
				trgn=translate[grn]
			reg_dict[trgn]=getattr(dest_regs, grn)
		reg_dict["ss"]="0x2b"
		reg_dict["cs"]="0x33"
		reg_dict["mode"]="NATIVE"

		het_log(reg_dict)
		dst_info["gpregs"]=reg_dict

		##fpregs
		het_log("WARNING: floating point registers not fully supported")
		dst_info["fpregs"]= {
			"cwd": 895, "swd": 0, "twd": 0, "fop": 0,
			"rip": 5248671, "rdp": 140735536563788, "mxcsr": 8064, "mxcsr_mask": 65535,
			"st_space": [ 0, 0, 0, 0, 0, 0, 0, 0,
						0, 0, 0, 0, 0, 0, 0, 0,
						0, 0, 0, 0, 0, 0, 0, 0,
						0, 0, 0, 0, 0, 2147483648, 16386, 0],
			"xmm_space": [16, 48, 2343184048, 32767, 5384384, 0, 5261400, 0,
						0, 0, 1, 0, 0, 0, 20, 0, 
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
									0, 0, 0, 0, 0, 0, 0, 0] }
		} 
		#TLS
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

		#delete old entry and add the new one
		del pgm_img['entries'][0]['ti_aarch64'] 
		ordered_dict_prepend(pgm_img['entries'][0], 'thread_info', dst_info)
		ordered_dict_prepend(pgm_img['entries'][0], 'mtype', "X86_64")

		#convert tc
		#pgm_img['entries'][0]['tc']['cg_set'] = 2
		#pgm_img['entries'][0]['tc']['loginuid'] = 1003
		#pgm_img['entries'][0]['tc']['rlimits']["rlimits"] = self.__get_rlimits()
		#pgm_img['entries'][0]['thread_core']['creds']['uid'] = 1003
		#pgm_img['entries'][0]['thread_core']['creds']['euid'] = 1003
		#pgm_img['entries'][0]['thread_core']['creds']['suid'] = 1003
		#pgm_img['entries'][0]['thread_core']['creds']['fsuid'] = 1003
		
		het_log(pgm_img)
		return pgm_img

	#PRoblem of this approach: pointer to stack!!?
	"""
	def __move_stack(self, pages_file, pagemap_file, core_file, mm_file):
		#FIXME: another wy to find the region than using MAP_GROWSDOWN?
		mm_tmpl, pgmap_tmpl, cnt_tmpl = self.remove_region_type(mm_img, pagemap_img, pages_tmp, "MAP_GROWSDOWN")
		new_mm_tmpl= {	"start": "0x7fff99600000", 
				    "end": "0x7fff99e00000", 
				    "pgoff": 0, 
				    "shmid": 0, 
				    "prot": "PROT_READ | PROT_WRITE", 
				    "flags": "MAP_PRIVATE | MAP_ANON | MAP_GROWSDOWN", 
				    "status": "VMA_AREA_REGULAR | VMA_ANON_PRIVATE", 
				    "fd": -1 }
		self.__add_target_region(mm_img, pagemap_img, pages_tmp, new_mm_tmpl, pgmap_tmpl, cnt_tmpl)
	"""		

	def get_target_core(self, architecture, binary, pages_file, pagemap_file, core_file):
		#old_stack_tmpl, new_stack_tmpl = self.__move_stack(pages_file, pagemap_file, core_file, mm_file)
		target_start = time.time()
		# dest_regs=self.read_regs_from_memory(binary, architecture, pagemap_file, pages_file, X86Struct)
		dest_regs = X86Struct()
		target_regs = time.time()
		# dest_tls=self.read_tls_from_memory(binary, architecture, pagemap_file, pages_file)
		# target_tls = time.time()
		het_log( "x86_64", binary, architecture, pagemap_file, pages_file)
		
		src_core=self.get_src_core(core_file)
		target_src = time.time()
		dst_core=self.convert_to_dest_core(src_core, dest_regs, None)#, old_stack_tmpl, new_stack_tmpl)
		target_dst = time.time()
		het_log("get_target_core x86_64", (target_regs - target_start), (target_dst -target_src))
		return dst_core

	def get_target_files(self, files_path, mm_file, path_append, root_dir):
		files_img=self.load_image_file(files_path)
		fid, idx, bin_path=self.get_binary_info(files_path, mm_file, path_append)
		tmp_root_dir = root_dir
		tmp_root_dir += bin_path
		bin_path = tmp_root_dir
		path_x86_64=bin_path+"_x86-64"
		path_aarch64=bin_path+"_aarch64"
		assert(os.path.isfile(path_x86_64) and os.path.isfile(path_aarch64))
		
		#copy file to appropriate arch
		#copyfile(path_x86_64, bin_path)
		statinfo = os.stat(path_x86_64)
		files_img["entries"][idx]["reg"]["size"] = statinfo.st_size
		return files_img

	def get_vsyscall_template(self):
		mm={"start": "0xffffffffff600000", 
			"end": "0xffffffffff601000", 
			"pgoff": 0, 
			"shmid": 0, 
			"prot": "PROT_READ | PROT_EXEC", 
			"flags": "MAP_PRIVATE | MAP_ANON", 
			"status": "VMA_AREA_VSYSCALL | VMA_ANON_PRIVATE", 
			"fd": -1
			}
		return mm, None, None
    
	def get_vvar_template(self):
		mm={"start": "0x7fff99ec6000", 
			"end": "0x7fff99ec9000", 
			"pgoff": 0, 
			"shmid": 0, 
			"prot": "PROT_READ", 
			"flags": "MAP_PRIVATE | MAP_ANON", 
			"status": "VMA_AREA_REGULAR | VMA_ANON_PRIVATE | VMA_AREA_VVAR", 
			"fd": -1, 
			"madv": "0x10000"
			}
		#pgmap= { "vaddr": "0x7fff99ec7000", "nr_pages": 3, "flags": "PE_PRESENT"}
		### vvar is not dumped in the pagemap either neither in the page list -- TODO need to check the source code
		
		return mm, None, None

	def get_vdso_template(self):
		mm= {"start": "0x7fff99ec9000", 
			"end": "0x7fff99ecb000", 
			"pgoff": 0, 
			"shmid": 0, 
			"prot": "PROT_READ | PROT_EXEC", 
			"flags": "MAP_PRIVATE | MAP_ANON", 
			"status": "VMA_AREA_REGULAR | VMA_AREA_VDSO | VMA_ANON_PRIVATE", 
			"fd": -1
			}
		pgmap= { "vaddr": "0x7fff99ec9000", "nr_pages": 2, "flags": "PE_PRESENT"}

		dir_path=os.path.dirname(os.path.realpath(__file__))
		vdso_path=os.path.join(dir_path, "templates/", "x86_64_vdso.img.tmpl")

		het_log("vdso path", vdso_path)
		f=open(vdso_path, "rb")
		vdso=f.read()
		f.close()

		return mm, pgmap, vdso

	def get_target_mem(self, mm_file, pagemap_file,  pages_file, dest_path):
		gtm_t0 =time.time()
		mm_img=self.load_image_file(mm_file)
		pagemap_img=self.load_image_file(pagemap_file)
		
		gtm_t1 =time.time()
		copyfile(pages_file, dest_path)
		
		gtm_t2 =time.time()
		original_size=os.stat(dest_path).st_size
		page_tmp=open(dest_path, "r+b")
		
		gtm_t3 =time.time()
		ret_size = self.remove_region_type(mm_img, pagemap_img, page_tmp, original_size, "VDSO")
		if (ret_size > 0): 
			ret_size = self.add_target_region(mm_img, pagemap_img, page_tmp, ret_size, "VDSO")
			if (ret_size > 0): original_size = ret_size
		
		gtm_t4 =time.time()
		ret_size = self.remove_region_type(mm_img, pagemap_img, page_tmp, original_size, "VVAR")
		if (ret_size > 0): 
			ret_size = self.add_target_region(mm_img, pagemap_img, page_tmp, ret_size, "VVAR")
			if (ret_size > 0): original_size = ret_size
				
		ret_size= self.add_target_region(mm_img, pagemap_img, page_tmp, original_size, "VSYSCALL")
		
		gtm_t5 =time.time()
		page_tmp.close()
		
		gtm_t6 =time.time()
		het_log("gtm", (gtm_t1 -gtm_t0), (gtm_t2 -gtm_t1), (gtm_t3 -gtm_t2), (gtm_t4 -gtm_t3), (gtm_t5 - gtm_t4), (gtm_t6 -gtm_t5))
		return mm_img, pagemap_img, dest_path

	def transform_files_img(self, files_img):
		pass

	def transform_ttyinfo_img(self, tty_img):
		pass


### FROM x86_64 to aarch64
class Aarch64Converter(Converter):
	def __init__(self):
		Converter.__init__(self)

	def __get_rlimits(self):
		return [{"cur": 18446744073709551615, "max": 18446744073709551615}, 
                {"cur": 18446744073709551615, "max": 18446744073709551615}, 
                {"cur": 18446744073709551615, "max": 18446744073709551615}, 
                {"cur": 8388608, "max": 18446744073709551615}, 
                {"cur": 0, "max": 18446744073709551615}, 
                {"cur": 18446744073709551615, "max": 18446744073709551615}, 
                {"cur": 515133, "max": 515133}, 
                {"cur": 1024, "max": 100000}, #x86_64 is {"cur": 8192, "max": 100000}, 
                {"cur": 18446744073709551615, "max": 18446744073709551615}, #x86_64 is {"cur": 65536, "max": 65536}, 
                {"cur": 18446744073709551615, "max": 18446744073709551615}, 
                {"cur": 18446744073709551615, "max": 18446744073709551615}, 
                {"cur": 515133, "max": 515133}, 
                {"cur": 819200, "max": 819200}, 
                {"cur": 0, "max": 0}, 
                {"cur": 0, "max": 0}, 
                {"cur": 18446744073709551615, "max": 18446744073709551615}]
    
	def get_vsyscall_template(self):
		return None, None, None

	def get_vvar_template(self):
		mm={ "start": "0xffffacaa5000", 
			    "end": "0xffffacaa6000", 
			    "pgoff": 0, 
			    "shmid": 0, 
			    "prot": "PROT_READ", 
			    "flags": "MAP_PRIVATE | MAP_ANON", 
			    "status": "VMA_AREA_REGULAR | VMA_ANON_PRIVATE | VMA_AREA_VVAR", 
			    "fd": -1
			}
		
		###TODO where is pgmap= ?

		return mm, None, None

	def get_vdso_template(self):
		mm= { "start": "0xffffacaa6000", 
			    "end": "0xffffacaa7000", 
			    "pgoff": 0, 
			    "shmid": 0, 
			    "prot": "PROT_READ | PROT_EXEC", 
			    "flags": "MAP_PRIVATE | MAP_ANON", 
			    "status": "VMA_AREA_REGULAR | VMA_AREA_VDSO | VMA_ANON_PRIVATE", 
			    "fd": -1
			} 
		pgmap={"vaddr": "0xffffacaa6000", 
		    "nr_pages": 1, 
		    "flags": "PE_PRESENT"}
		dir_path=os.path.dirname(os.path.realpath(__file__))
		vdso_path=os.path.join(dir_path, "templates/", "aarch64_vdso.img.tmpl")
		het_log("vdso path", vdso_path)
		f=open(vdso_path, "rb")
		vdso=f.read(PAGE_SIZE)
		f.close()

		return mm, pgmap, vdso

	def convert_to_dest_core(self, pgm_img, dest_regs, dest_tls):
		###convert the type
		pgm_img['entries'][0]['mtype']="AARCH64"

		###convert thread_info
		src_info=pgm_img['entries'][0]['thread_info']
		dst_info=OrderedDict() 
		dst_info["clear_tid_addr"]=src_info["clear_tid_addr"]
		dst_info["tls"]=dest_tls
		
		##gpregs
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
		##fpsimd
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
		del pgm_img['entries'][0]['thread_info']
		pgm_img['entries'][0]['ti_aarch64'] = dst_info

		#convert tc
		#pgm_img['entries'][0]['tc']['cg_set'] = 1
		#pgm_img['entries'][0]['tc']['loginuid'] = 1004
		#pgm_img['entries'][0]['tc']['rlimits']["rlimits"] = self.__get_rlimits()
		#pgm_img['entries'][0]['thread_core']['creds']['uid'] = 1004
		#pgm_img['entries'][0]['thread_core']['creds']['euid'] = 1004
		#pgm_img['entries'][0]['thread_core']['creds']['suid'] = 1004
		#pgm_img['entries'][0]['thread_core']['creds']['fsuid'] = 1004
		return pgm_img
		
	
	def get_target_core(self, architecture, binary, pages_file, pagemap_file, core_file):
		target_start = time.time()
		# dest_regs=self.read_regs_from_memory(binary, architecture, pagemap_file, pages_file, Aarch64Struct)
		dest_regs = Aarch64Struct()
		target_regs = time.time()
		dest_tls = 281474840395760 #TODO: research and add logic to this to add multithreading support
		# dest_tls=self.read_tls_from_memory(binary, architecture, pagemap_file, pages_file)
		# target_tls = time.time()
		het_log( "aarch64", binary, architecture, pagemap_file, pages_file)
		src_core=self.get_src_core(core_file)
		target_src= time.time()
		dst_core=self.convert_to_dest_core(src_core, dest_regs, dest_tls)
		target_dst = time.time()
		het_log("get_target_core aarch64", (target_regs - target_start), (target_dst -target_src))
		return dst_core
	
	def get_target_mem(self, mm_file, pagemap_file,  pages_file, dest_path):
		gtm_t0 =time.time()
		mm_img=self.load_image_file(mm_file)
		pagemap_img=self.load_image_file(pagemap_file)

		gtm_t1 =time.time()
		copyfile(pages_file, dest_path)	

		gtm_t2 =time.time()
		original_size=os.stat(dest_path).st_size
		page_tmp=open(dest_path, "r+b")
		
		gtm_t3 =time.time()
		ret_size = self.remove_region_type(mm_img, pagemap_img, page_tmp, original_size, "VDSO")
		if (ret_size > 0):
			ret_size = self.add_target_region(mm_img, pagemap_img, page_tmp, ret_size, "VDSO")
			if (ret_size > 0): original_size = ret_size
		
		gtm_t4 =time.time()
		ret_size = self.remove_region_type(mm_img, pagemap_img, page_tmp, original_size, "VVAR")
		if (ret_size > 0):
			ret_size = self.add_target_region(mm_img, pagemap_img, page_tmp, original_size, "VVAR")
			if (ret_size > 0): original_size = ret_size
		
		ret_size = self.remove_region_type(mm_img, pagemap_img, page_tmp, original_size, "VSYSCALL")
		
		gtm_t5 =time.time()
		page_tmp.close()
		
		gtm_t6 =time.time()
		het_log("gtm", (gtm_t1 -gtm_t0), (gtm_t2 -gtm_t1), (gtm_t3 -gtm_t2), (gtm_t4 -gtm_t3), (gtm_t5 - gtm_t4), (gtm_t6 -gtm_t5))
		return mm_img, pagemap_img, dest_path

	def get_target_files(self, files_path, mm_file, path_append, root_dir):
		files_img=self.load_image_file(files_path)
		fid, idx, bin_path=self.get_binary_info(files_path, mm_file, path_append)
		tmp_root_dir = root_dir
		tmp_root_dir += bin_path
		bin_path = tmp_root_dir
		print(bin_path) 
		path_x86_64=bin_path+"_x86-64"
		path_aarch64=bin_path+"_aarch64"
		assert(os.path.isfile(path_x86_64) and os.path.isfile(path_aarch64))
		#copy file to appropriate arch
		#copyfile(path_aarch64, bin_path)
		statinfo = os.stat(path_aarch64)
		files_img["entries"][idx]["reg"]["size"] = statinfo.st_size
		return files_img
	
	def transform_files_img(self, files_img):
		assert(os.path.isfile(files_img))
		files_obj = self.load_image_file(files_img, True)
		rfile_flags_map = pb2dict.rfile_flags_map
		o_rdwr = [v[1] for v in rfile_flags_map if v[0] == "O_RDWR"][0]
		o_append = [v[1] for v in rfile_flags_map if v[0] == "O_APPEND"][0]
		o_nofollow = [v[1] for v in rfile_flags_map if v[0] == "O_NOFOLLOW"][0]
		tty_ent_templ = {
			"type": "TTY",
			"id": 2,
			"tty": {
				"id": 2,
				"tty_info_id": 2020,
				"regf_id": 3,
				"flags": "0x20402",
				"fown": {
					"uid": 0,
					"euid": 0,
					"signum": 0,
					"pid_type": 0,
					"pid": 0
				}
			}
		}
		reg_ent_templ = {
			"type": "REG",
			"id": 3,
			"reg": {
				"id": 3, 
				"flags": o_rdwr | o_append | o_nofollow,
				"pos": 0,
				"name": "/dev/ttyAMA0",
				"mode": 8576,
				"fown": {
					"uid": 0,
					"euid": 0,
					"signum": 0,
					"pid_type": 0,
					"pid": 0
				}
			}
		}
		tty_entry_i = [i for i in range(len(files_obj["entries"])) if \
			files_obj["entries"][i]["type"] == "TTY"][0]
		tty_ent_templ["id"] = files_obj["entries"][tty_entry_i]["id"]
		tty_ent_templ["tty"]["id"] = files_obj["entries"][tty_entry_i]["tty"]["id"]
		tty_ent_templ["tty"]["regf_id"] = files_obj["entries"][tty_entry_i]["tty"]["regf_id"]
		regf_id = files_obj["entries"][tty_entry_i]["tty"]["regf_id"]
		regf_entry_i = [i for i in range(len(files_obj["entries"])) if \
			files_obj["entries"][i]["id"] == regf_id][0]
		reg_ent_templ["id"] = files_obj["entries"][regf_entry_i]["id"]
		reg_ent_templ["reg"]["id"] = files_obj["entries"][regf_entry_i]["reg"]["id"]
		files_obj["entries"][tty_entry_i] = tty_ent_templ
		files_obj["entries"][regf_entry_i] = reg_ent_templ
		f = open(files_img, 'wb')
		pycriu.images.dump(files_obj, f)
		f.close()

	def transform_ttyinfo_img(self, tty_img):
		pass


def test_convert_core():
	pid=3614
	binary="/share/karaoui/criu-project/popcorn-compiler/tests/hello/test"
	pages_file="/share/karaoui/criu-project/dumps/hello/new-dump/pages-1.img"
	pagemap_file="/share/karaoui/criu-project/dumps/hello/new-dump/pagemap-"+str(pid)+".img"
	core_file="/share/karaoui/criu-project/dumps/hello/new-dump/core-"+str(pid)+".img"
	architecture=1
	#FIXME
	dst_core=None #get_target_core(architecture, binary, pages_file, pagemap_file, core_file)
	#f = open("new_core."+str(architecture), "w+")
	f = sys.stdin
	json.dump(dst_core, f, indent=4)
	if f == sys.stdout:
		f.write("\n")

if __name__ == '__main__':
	test_convert_core()
