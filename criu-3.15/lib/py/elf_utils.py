"""
Copyright (c) 2021. Abhishek Bapat. SSRG, Virginia Tech.
abapat28@vt.edu
"""

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import os
import sys

SCN_MAGIC = 0x012c747d

def open_elf_file(dir, bin):
    f = open(os.path.join(dir, bin), 'rb')
    elffile = ELFFile(f)
    return elffile

def open_elf_file_fp(bin):
    f = open(bin, 'rb')
    elffile = ELFFile(f)
    return elffile

def get_elf_section(elffile, section_name = ''):
    if section_name == '':
        return [section for section in elffile.iter_sections()]
    else:
        return [section for section in elffile.iter_sections() if section.name == section_name][0]
    
def get_num_entries(section):
    if section.header.sh_entsize:
        return section.header.sh_size // section.header.sh_entsize
    return -1

def get_function_offset(file, function):
    try:
        with open(file, 'rb') as f:
            elffile = ELFFile(f)
            func_info = list()
            for section in elffile.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                for symbol in section.iter_symbols():
                    if symbol.name == function:
                        return symbol['st_value']
    except Exception as e:
        print('Could not process request: {}'.format(e))    

def find_functions(file):
    """ Locate functions and their offset.

    Note: Offsets returned are relative to the start of
    the file.

    Args:
        file: Path to the file.

    Return:
        List of dict in following format
        [
            {'name' : function name,
             'saddr': (start address of the function in source binary,
                        start address of the function in pages-1.img)
             'eaddr': (end address of the function in source binary,
                        end address of the function in pages-1.img)
            },
        ]
    """
    def is_function(symbol):
        """ Check if the symbol pertains to a user defined
        function.

        Filters all relocatable (PIE) functions and library
        functions included by the compiler.
        """
        return symbol['st_info']['type'] == 'STT_FUNC' \
               and symbol['st_shndx'] != 'SHN_UNDEF' \
               and symbol['st_size'] and \
               symbol.name 
               # and '_' not in symbol.name

    try:
        with open(file, 'rb') as f:
            elffile = ELFFile(f)
            func_info = list()
            for section in elffile.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue
                func_info.extend([{'name': symbol.name,
                        'saddr': {'exe_offset': int(symbol['st_value']), 'criu_offset': 0, 'criu_size': 0},
                        'eaddr': {'exe_offset': int(symbol['st_value'] + symbol['st_size']), 'criu_offset': 0}}
                        for symbol in section.iter_symbols() if is_function(symbol)])
            # Remove redundant dict entries if any
            #func_info = {frozenset(info.items()) : info for info in func_info}.values()
            
        return(list(func_info))

    except Exception as e:
        print('Could not process request: {}'.format(e))