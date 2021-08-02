import struct

from . import definitions
from . import reg_aarch64
from . import reg_x86_64


def rewrite_stack(core, elffile_src, elffile_dest, page_map, pages):
    if core['mtype'] == 'AARCH64':
        src_handle = definitions.StHandle(definitions.AARCH64, elffile_src)
        dest_handle = definitions.StHandle(definitions.X86_64, elffile_dest)
    else:
        src_handle = definitions.StHandle(definitions.X86_64, elffile_src)
        dest_handle = definitions.StHandle(definitions.AARCH64, elffile_dest)
    assert src_handle.type != dest_handle.type,\
        "Same src and dest arch type. Does not need transformation!"
    if src_handle.type == definitions.X86_64:
        src_regset = reg_x86_64.RegsetX8664(core)
        dest_regset = reg_aarch64.RegsetAarch64()
    else:
        src_regset = reg_aarch64.RegsetAarch64(core)
        dest_regset = reg_x86_64.RegsetX8664()
    rewrite_context_init(page_map, pages, src_handle,
                         src_regset, dest_handle, dest_regset)


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
    return call_site.id == definitions.UINT64_MAX


def pop_frame(ctx, sp, bp):
    offset = ctx.stack_top_offset + (bp - sp)
    ctx.pages.seek(offset)
    bp = struct.unpack('<Q', ctx.pages.read(8))[0]
    pc = struct.unpack('<Q', ctx.pages.read(8))[0]
    return (bp, pc)


def unwind_and_size(src_rewrite_ctx, dest_rewrite_ctx):
    src_handle = src_rewrite_ctx.st_handle
    dest_handle = dest_rewrite_ctx.st_handle
    dest_stack_size = 0
    src_pc = src_handle.regops['pc'](src_rewrite_ctx.regset)
    src_sp = src_handle.regops['sp'](src_rewrite_ctx.regset)
    src_bp = src_handle.regops['bp'](src_rewrite_ctx.regset)
    while True:
        src_cs = src_handle.get_call_site_from_addr(src_pc)
        dest_cs = dest_handle.get_call_site_from_id(src_cs.id)
        src_act = definitions.Activation(src_cs, src_cs.frame_size)
        dest_act = definitions.Activation(dest_cs, dest_cs.frame_size)
        src_rewrite_ctx.activations.append(src_act)
        dest_rewrite_ctx.activations.append(dest_act)
        dest_stack_size += dest_cs.frame_size
        (src_bp, src_pc) = pop_frame(src_rewrite_ctx, src_sp, src_bp)
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
    src_rewrite_ctx = definitions.RewriteContext(
        src_handle, src_regset, stack_top_offset, stack_base_offset, pages)
    dest_rewrite_ctx = definitions.RewriteContext(dest_handle, dest_regset)
    unwind_and_size(src_rewrite_ctx, dest_rewrite_ctx)
    print("Test")