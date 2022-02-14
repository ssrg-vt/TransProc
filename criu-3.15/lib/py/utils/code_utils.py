from capstone import *
import sys
import mmap
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils import elf_utils

def get_code_region(mmi, pms, exe):
    """ Function to obtain the function list and their offsets 
    within pages-%.img

    Args:
        mmi: Memory map info obtained from mm-%.img
        pms: Page map info obtained from pagemap-%img
        exe: Path to the executable file whose process was
        checkpointed

    Return:
        Returns tuple with following information.
            (pages-%d.img name resolved,
            [
                {'name' : function name,
                'saddr': start address of the function,
                'eaddr': end address of the function
                },
            ])
    """
    def adjust_code_offset(info):
        info['saddr']['exe_offset'] = info['saddr']['exe_offset'] - 0x400000
        info['eaddr']['exe_offset'] = info['eaddr']['exe_offset'] - 0x400000
        
        return info

    start_code = mmi['mm_start_code']
    func_info = elf_utils.find_functions(exe)    

    for func in func_info:
        found_pmap = False        
        offset_pages = 0
        offset_bytes = 0
        for pmap in pms[1:]:
            if pmap['vaddr'] <= func['saddr']['exe_offset'] < pmap['vaddr'] + pmap['nr_pages'] * mmap.PAGESIZE:
                offset_bytes = func['saddr']['exe_offset'] - pmap['vaddr']
                found_pmap = True
                break
            else:
                offset_pages += pmap['nr_pages']
                continue
        
        if found_pmap:
            func['saddr']['criu_offset'] = offset_pages * mmap.PAGESIZE + offset_bytes
            size = func['eaddr']['exe_offset'] - func['saddr']['exe_offset']
            func['eaddr']['criu_offset'] = offset_pages * mmap.PAGESIZE + offset_bytes + size
            
            func['saddr']['criu_size'] =  size if func['eaddr']['exe_offset'] <= pmap['vaddr'] + pmap['nr_pages'] * mmap.PAGESIZE \
                                                else pmap['vaddr'] + pmap['nr_pages'] * mmap.PAGESIZE - func['saddr']['exe_offset']

    func_info = map(adjust_code_offset,func_info)
    file = 'pages-%d.img' % (pms[0]['pages_id'])
    return (file, list(func_info))
