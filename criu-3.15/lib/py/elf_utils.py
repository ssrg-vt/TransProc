from elftools.elf.elffile import ELFFile
import os

def open_elf_file(dir, bin):
    f = open(os.path.join(dir, bin), 'rb')
    elffile = ELFFile(f)
    return elffile

def get_elf_section(elffile, section_name = ''):
    if section_name == '':
        return [section for section in elffile.iter_sections()]
    else:
        return [section for section in elffile.iter_sections() if section.name == section_name][0]