from . import definitions
from . import reg_aarch64
from . import reg_x86_64
from definitions import *


def rewrite_stack(core_src, elffile_src, core_dest, elffile_dest, ps_tree, page_map, pages):
    src_handle = StHandle(core_src, elffile_src)
    dest_handle = StHandle(core_dest, elffile_dest)
    assert src_handle.type != dest_handle.type,\
        "Same src and dest arch type. Does not need transformation!"
    if src_handle.type == X86_64:
        src_regset = reg_x86_64.RegsetX8664(core_src)
        dest_regset = reg_aarch64.RegsetAarch64()
    else:
        src_regset = reg_aarch64.RegsetAarch64(core_src)
        dest_regset = reg_x86_64.RegsetX8664()


def get_stack_page_offset(page_map, sp):
    pages_to_skip = 0
    st_vaddr = 0
    end_vaddr = 0
    for pm in page_map[1:]:
        nr_pages = pm['nr_pages']
        st_vaddr = pm['vaddr']
        end_vaddr = st_vaddr + (nr_pages << 12)
        if(sp > end_vaddr):
            pages_to_skip += nr_pages
            continue
        else:
            break
    return (pages_to_skip, st_vaddr, end_vaddr)


def first_frame(call_site):
    return call_site.id == UINT64_MAX


def unwind_and_size(src_rewrite_ctx, dest_rewrite_ctx):
    src_handle = src_rewrite_ctx.st_handle
    dest_handle = dest_rewrite_ctx.st_handle
    while True:
        src_cs = src_handle.get_call_site_from_addr(src_handle.regops['pc'](src_rewrite_ctx.regset))
        dest_cs = dest_handle.get_call_site_from_id(src_cs.id)
        
        if first_frame(src_cs):
            break


def rewrite_context_init(page_map, pages, src_handle, src_regset, dest_handle, dest_regset):
    pages_to_skip = 0
    sp = src_handle.regops['sp'](src_regset)
    (pages_to_skip, st_vaddr, end_vaddr) = get_stack_page_offset(page_map, sp)
    assert pages_to_skip != 0 and st_vaddr != 0 and end_vaddr != 0,\
        "Something went wrong reading src stack"
    stack_top_offset = (pages_to_skip << 12) + (sp - st_vaddr)
    stack_base_offset = (pages_to_skip << 12) + (end_vaddr - st_vaddr)
    src_rewrite_ctx = RewriteContext(src_handle, stack_top_offset, stack_base_offset,
                                     src_regset, pages)
    dest_rewrite_ctx = RewriteContext(dest_handle, dest_regset)
    unwind_and_size(src_rewrite_ctx, dest_rewrite_ctx)
