import sys
import mmap
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils import elf_utils


def get_stack_pointers(core):
    arch = core['entries'][0]['mtype']
    regs = core['entries'][0]
    if arch.upper() in ('X86_64'):
        bp, sp, pc = regs['thread_info']['gpregs']['bp'], \
                     regs['thread_info']['gpregs']['sp'], \
                     regs['thread_info']['gpregs']['ip']
                     
    elif arch.upper() in ('AARCH64'):
        # Note: In AARCH64 with frame pointer x29(fp) = sp
        # Calculate the frame start (bp) later during stack frame walk 
        bp, sp, pc = regs['ti_aarch64']['gpregs']['regs'][29], \
                     regs['ti_aarch64']['gpregs']['sp'], \
                     regs['ti_aarch64']['gpregs']['pc']
    else:
        raise Exception("Unsupported Architecture")
    return bp,sp,pc

def get_top_stack_frame(mmi, pms, core , exe):

    def adjust_code_offset(info):
        info['saddr'][0] =  start_code + info['saddr'][0]
        info['eaddr'][0] =  start_code + info['eaddr'][0]
        return info

    bp, sp, ip = get_stack_pointers(core)
    start_code = mmi['mm_start_code']
    func_info = elf_utils.find_functions(exe)
    offset_pages = 0
    offset_bytes = 0
    for pmap in pms[1:]:
        if pmap['vaddr'] <= sp < pmap['vaddr'] + pmap['nr_pages'] * mmap.PAGESIZE:
            offset_bytes = sp - pmap['vaddr']
            break
        else:
            offset_pages += pmap['nr_pages']
            continue
    if bp < sp:
        return None
    bp -= sp
    offset_sp = offset_pages * mmap.PAGESIZE + offset_bytes
    offset_bp = bp + offset_sp
    file = 'pages-%d.img' % (pms[0]['pages_id'])
    return (file, ip, sp, offset_sp, offset_bp, list(func_info))
