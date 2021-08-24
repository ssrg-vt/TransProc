from io import RawIOBase
import struct
import os

from . import definitions
from . import reg_aarch64
from . import reg_x86_64
from pycriu import utils


def rewrite_stack(core, elffile_src, elffile_dest, page_map, pages, dest_st_fn, opts):
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
    (src_ctx, dest_ctx) = rewrite_context_init(page_map, pages, src_handle, src_regset,
                                               dest_handle, dest_regset, dest_st_fn, opts)
    assert len(src_ctx.activations) == len(dest_ctx.activations), \
            "Activation count unequal for src and dest"
    for i in range(len(dest_ctx.activations)):
        src_ctx.act = i
        dest_ctx.act = i
        # TODO Handle return address
        rewrite_frame(src_ctx, dest_ctx)
    dest_ctx.pages.close()
    print("Transformed stack in file: %s" % os.path.join(opts['dir'], dest_st_fn))

def rewrite_frame(src_ctx, dest_ctx):
    src_cs = src_ctx.activations[src_ctx.act].call_site
    dest_cs = dest_ctx.activations[dest_ctx.act].call_site
    src_offset = src_cs.live_offset
    dest_offset = dest_cs.live_offset
    needs_fixup = False
    put_frame_ptr(dest_ctx)
    i = j = 0
    while(j < dest_cs.num_live):
        src_val = src_ctx.st_handle.live_vals[i+src_offset]
        dest_val = dest_ctx.st_handle.live_vals[j+dest_offset]
        needs_fixup |= rewrite_val(src_ctx, src_val, dest_ctx, dest_val)
        while(j+1+dest_offset < dest_ctx.st_handle.live_val_entries and
              dest_ctx.st_handle.live_vals[j+1+dest_offset].is_duplicate):
            j += 1
            needs_fixup |= rewrite_val(src_ctx, src_val, dest_ctx, dest_val)
        while(i+1+src_offset < src_ctx.st_handle.live_val_entries and
              src_ctx.st_handle.live_vals[i+1+src_offset].is_duplicate):
            i += 1
        i += 1
        j += 1
    i = 0
    while(i < dest_cs.num_arch_live):
        raw_val = get_val(
            dest_ctx, dest_ctx.st_handle.arch_live_vals[i+dest_cs.arch_live_offset], True)
        raw_val = get_arch_val(dest_ctx,
                               dest_ctx.st_handle.arch_live_vals[i + dest_cs.arch_live_offset],
                               raw_val)
        put_val(dest_ctx,
                dest_ctx.st_handle.arch_live_vals[i+dest_cs.arch_live_offset],
                raw_val,
                True)
        i += 1
    return needs_fixup


# Adds the next frame pointer and return address to the stack.
def put_frame_ptr(ctx):
    if ctx.act == len(ctx.activations)-1:
        return
    regops = ctx.st_handle.regops
    act = ctx.activations[ctx.act]
    act_next = ctx.activations[ctx.act + 1]
    sp = regops['sp'](act.regset)
    bp = regops['bp'](act.regset)
    offset = bp - sp
    fp = bp + act_next.call_site.frame_size
    fp_bytes = struct.pack("Q", fp)
    ctx.pages.seek(offset)
    ctx.pages.write(fp_bytes)
    ctx.pages.seek(offset + 8)
    addr = act_next.call_site.addr
    addr_bytes = struct.pack("Q", addr)
    ctx.pages.write(addr_bytes)



def get_arch_val(ctx, arch_live_val, raw_val):
    regops = ctx.st_handle.regops
    if arch_live_val.is_gen:
        if arch_live_val.operand_type == definitions.SM_REGISTER:
            reg = regops['reg_val'](
                arch_live_val.operand_regnum, ctx.activations[ctx.act].regset)
            if arch_live_val.inst_type == definitions.Set:
                raw_val = reg
            elif arch_live_val.inst_type == definitions.Add:
                raw_val += reg
            elif arch_live_val.inst_type == definitions.Sub:
                raw_val -= reg
            elif arch_live_val.inst_type == definitions.Mult:
                raw_val *= reg
            elif arch_live_val.inst_type == definitions.Divide:
                raw_val //= reg
            elif arch_live_val.inst_type == definitions.LShift:
                raw_val <<= reg
            elif arch_live_val.inst_type == definitions.RShiftLog:
                raw_val >>= reg
            elif arch_live_val.inst_type == definitions.RShiftArith:
                raw_val >>= reg  # TODO: Handle properly
            elif arch_live_val.inst_type == definitions.Mask:
                raw_val &= reg
            else:
                raise Exception("Invalid instruction type %d" %
                                arch_live_val.inst_type)
            return raw_val
        elif arch_live_val.operand_type == definitions.SM_CONSTANT:
            const = arch_live_val.operand_offset_or_constant
            if arch_live_val.inst_type == definitions.Set:
                raw_val = const
            elif arch_live_val.inst_type == definitions.Add:
                raw_val += const
            elif arch_live_val.inst_type == definitions.Sub:
                raw_val -= const
            elif arch_live_val.inst_type == definitions.Mult:
                raw_val *= const
            elif arch_live_val.inst_type == definitions.Divide:
                raw_val //= const
            elif arch_live_val.inst_type == definitions.LShift:
                raw_val <<= const
            elif arch_live_val.inst_type == definitions.RShiftLog:
                raw_val >>= const  # TODO: Handle properly
            elif arch_live_val.inst_type == definitions.RShiftArith:
                raw_val >>= const
            elif arch_live_val.inst_type == definitions.Mask:
                raw_val &= const
            else:
                raise Exception("Invalid instruction type %d" %
                                arch_live_val.inst_type)
            return raw_val
        else:
            raise Exception("Invalid operand type %ld" %
                            arch_live_val.operand_type)
    else:
        reg = regops['reg_val'](
            arch_live_val.operand_regnum, ctx.activations[ctx.act].regset)
        if arch_live_val.operand_type == definitions.SM_REGISTER:
            raw_val = reg
        elif arch_live_val.operand_type == definitions.SM_DIRECT or \
                arch_live_val.operand_type == definitions.SM_INDIRECT:
            st_addr = reg + arch_live_val.operand_offset_or_constant
            act = ctx.activations[ctx.act]
            sp = regops['sp'](act.regset)
            val_offset = (st_addr - sp) + ctx.stack_top_offset
            ctx.pages.seek(val_offset)
            if arch_live_val.operand_size == 1:
                raw_val = struct.unpack("<B", ctx.pages.read(1))[0]
            elif arch_live_val.operand_size == 2:
                raw_val = struct.unpack("<H", ctx.pages.read(2))[0]
            elif arch_live_val.operand_size == 4:
                raw_val = struct.unpack("<I", ctx.pages.read(4))[0]
            elif arch_live_val.operand_size == 8:
                raw_val = struct.unpack("<Q", ctx.pages.read(8))[0]
            else:
                raise Exception("operand size not supported")
        elif arch_live_val.operand_type == definitions.SM_CONSTANT:
            raw_val = arch_live_val.operand_offset_or_constant
        else:
            raise Exception("Invalid operand type %ld" %
                            arch_live_val.operand_type)
        return raw_val


def rewrite_val(src_ctx, src_val, dest_ctx, dest_val):
    skip = need_local_fix = False
    if dest_val.is_temp:
        return False
    if src_val.is_alloca and src_val.alloca_size == 24 and \
       dest_val.is_alloca and dest_val.alloca_size == 32:
        skip = True
    elif src_val.is_alloca and src_val.alloca_size == 32 and \
            dest_val.is_alloca and dest_val.alloca_size == 24:
        skip = True
    elif src_val.is_alloca and src_val.alloca_size == 24 and \
            dest_val.is_alloca and dest_val.alloca_size == 8:
        skip = True
    elif src_val.is_alloca and src_val.alloca_size == 8 and \
            dest_val.is_alloca and dest_val.alloca_size == 24:
        skip = True
    src_regops = src_ctx.st_handle.regops
    src_sp = src_regops['sp'](src_ctx.regset)
    if skip:
        return False
    stack_addr = points_to_stack(src_ctx, src_val)
    if stack_addr:
        if src_ctx.act == 0 or (stack_addr-src_sp) >= src_ctx.activations[src_ctx.act-1].cfo:
            fixup_data = definitions.Fixup(
                stack_addr, src_sp, dest_ctx.act, dest_val)
            dest_ctx.stack_pointers.append(fixup_data)
            src_bp = src_regops['bp'](src_ctx.activations[2].regset)
            if (src_bp - stack_addr) < src_ctx.activations[src_ctx.act].cfo:
                need_local_fix = True
        # else:
            # Warn "Pointer to stack points to called functions\n"
    else:
        raw_val = get_val(src_ctx, src_val)
        put_val(dest_ctx, dest_val, raw_val)
    return need_local_fix


def put_val(dest_ctx, dest_val, raw_val, arch=False):
    dest_act = dest_ctx.activations[dest_ctx.act]
    regops = dest_ctx.st_handle.regops
    if dest_val.type == definitions.SM_REGISTER:
        regops['set_reg'](dest_val.regnum, raw_val, dest_act.regset)
    elif dest_val.type == definitions.SM_DIRECT or dest_val.type == definitions.SM_INDIRECT:
        st_addr = regops['reg_val'](
            dest_val.regnum, dest_act.regset) + dest_val.offset_or_const
        sp = regops['sp'](dest_act.regset)
        val_offset = (st_addr - sp) + dest_ctx.stack_top_offset
        dest_ctx.pages.seek(val_offset)
        write_count = 1
        write_val = []
        if not arch:
            if dest_val.is_alloca:
                if dest_val.alloca_size == 1:
                    write_val.append(struct.pack("B", raw_val))
                elif dest_val.alloca_size == 2:
                    write_val.append(struct.pack("H", raw_val))
                elif dest_val.alloca_size == 4:
                    write_val.append(struct.pack("I", raw_val))
                elif dest_val.alloca_size == 8:
                    write_val.append(struct.pack("Q", raw_val))
                else:
                    write_count = dest_val.alloca_size//8
                    for i in range(write_count):
                        write_val.append(struct.pack("Q", raw_val[i]))
            else:
                write_val.append(struct.pack("Q", raw_val))
        else:
            if dest_val.operand_size == 1:
                write_val.append(struct.pack("B", raw_val))
            elif dest_val.operand_size == 2:
                write_val.append(struct.pack("H", raw_val))
            elif dest_val.operand_size == 4:
                write_val.append(struct.pack("I", raw_val))
            elif dest_val.operand_size == 8:
                write_val.append(struct.pack("Q", raw_val))
            else:
                raise Exception("Operand size not supported")
        for i in range(write_count):
            dest_ctx.pages.write(write_val[i])
    else:
        raise Exception("Value type %ld not supported" % dest_val.type)


def get_val(ctx, val, arch=False):
    act = ctx.activations[ctx.act]
    regops = ctx.st_handle.regops
    sp = regops['sp'](act.regset)
    if val.type == definitions.SM_REGISTER:
        return regops['reg_val'](val.regnum, ctx.regset) ## TODO: Determine whether ctx or act
    elif val.type == definitions.SM_DIRECT or val.type == definitions.SM_INDIRECT:
        st_addr = regops['reg_val'](
            val.regnum, act.regset) + val.offset_or_const
        val_offset = (st_addr - sp) + ctx.stack_top_offset
        ctx.pages.seek(val_offset)
        if not arch:
            if val.is_alloca:
                if val.alloca_size == 1:
                    raw_val = struct.unpack('<B', ctx.pages.read(1))[0]
                elif val.alloca_size == 2:
                    raw_val = struct.unpack('<H', ctx.pages.read(2))[0]
                elif val.alloca_size == 4:
                    raw_val = struct.unpack('<I', ctx.pages.read(4))[0]
                elif val.alloca_size == 8:
                    raw_val = struct.unpack('<Q', ctx.pages.read(8))[0]
                else:
                    c = val.alloca_size//8
                    raw_val = []
                    for _ in range(c):
                        raw_val.append(struct.unpack('<Q', ctx.pages.read(8))[0])
            else:
                raw_val = struct.unpack('<Q', ctx.pages.read(8))[0]
        else:
            raw_val = struct.unpack('<Q', ctx.pages.read(8))[0]
        return raw_val
    elif val.type == definitions.SM_CONSTANT or val.type == definitions.SM_CONST_IDX:
        raise Exception("Cannot get val for constant/constant loc")
    else:
        raise Exception("Unsupported value type")


def points_to_stack(ctx, live_val):
    regops = ctx.st_handle.regops
    sp = regops['sp'](ctx.regset)
    act = ctx.activations[ctx.act]
    if live_val.is_ptr:
        if live_val.type == definitions.SM_REGISTER:
            stack_addr = regops['reg_val'](live_val.regnum, ctx.regset)
        elif live_val.type == definitions.SM_DIRECT or live_val.type == definitions.SM_INDIRECT:
            st_addr = regops['reg_val'](
                live_val.regnum, act.regset) + live_val.offset_or_const
            val_offset = (st_addr - sp) + ctx.stack_top_offset
            ctx.pages.seek(val_offset)
            stack_addr = struct.unpack('<Q', ctx.pages.read(8))[0]
        elif live_val.type == definitions.SM_CONSTANT:
            raise Exception(
                "Directly encoded constant too small to store ptrs")
        elif live_val.type == definitions.SM_CONST_IDX:
            raise Exception("constant pool entries not supported")
        else:
            raise Exception("invalid value type %d" % live_val.type)

        if (stack_addr - sp) < 0 or \
            (stack_addr - sp + ctx.stack_top_offset) >= ctx.stack_base_offset:
            stack_addr = None
        return stack_addr
    else:
        return None


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
    d = src_bp - src_sp
    dest_sp = 0xfffffffff8b0
    dest_bp = dest_sp + d
    dest_handle.regops['set_sp'](dest_sp, dest_rewrite_ctx.regset)
    dest_handle.regops['set_bp'](dest_bp, dest_rewrite_ctx.regset)
    while True:
        if src_handle.type == definitions.X86_64:
            src_act_regset = reg_x86_64.RegsetX8664()
            dest_act_regset = reg_aarch64.RegsetAarch64()
        else:
            src_act_regset = reg_aarch64.RegsetAarch64
            dest_act_regset = reg_x86_64.RegsetX8664()
        src_cs = src_handle.get_call_site_from_addr(src_pc)
        dest_cs = dest_handle.get_call_site_from_id(src_cs.id)
        if len(dest_rewrite_ctx.activations) > 0:
            dest_bp += dest_cs.frame_size
        src_handle.regops['set_sp'](src_sp, src_act_regset)
        src_handle.regops['set_bp'](src_bp, src_act_regset)
        dest_handle.regops['set_sp'](dest_sp, dest_act_regset)
        dest_handle.regops['set_bp'](dest_bp, dest_act_regset)
        src_act = definitions.Activation(
            src_cs, src_cs.frame_size, src_act_regset)
        dest_act = definitions.Activation(
            dest_cs, dest_cs.frame_size, dest_act_regset)
        src_rewrite_ctx.activations.append(src_act)
        dest_rewrite_ctx.activations.append(dest_act)
        if len(dest_rewrite_ctx.activations) == 1:
            dest_handle.regops['set_pc'](dest_cs.addr, dest_rewrite_ctx.regset)
            dest_handle.regops['set_pc'](dest_cs.addr, dest_rewrite_ctx.activations[0].regset)
        dest_stack_size += dest_cs.frame_size
        (src_bp, src_pc) = pop_frame(src_rewrite_ctx, src_sp, src_bp)
        if first_frame(src_cs):
            break
    dest_rewrite_ctx.stack_size = dest_stack_size
    dest_rewrite_ctx.stack_base_offset = dest_stack_size
    dest_rewrite_ctx.pages.write(b'\x00' * dest_stack_size)



def rewrite_context_init(page_map, pages, src_handle, src_regset, dest_handle,
                         dest_regset, dest_st_fn, opts):
    sp = src_handle.regops['sp'](src_regset)
    (pages_to_skip, st_vaddr, end_vaddr) = get_stack_page_offset(page_map, sp)
    assert pages_to_skip != 0 and st_vaddr != 0 and end_vaddr != 0,\
        "Something went wrong reading src stack"
    stack_top_offset = (pages_to_skip << 12) + (sp - st_vaddr)
    stack_base_offset = (pages_to_skip << 12) + (end_vaddr - st_vaddr)
    src_rewrite_ctx = definitions.RewriteContext(
        src_handle, src_regset, stack_top_offset, stack_base_offset, pages)
    dest_rewrite_ctx = definitions.RewriteContext(dest_handle, dest_regset)
    dest_rewrite_ctx.pages = utils.doutf(opts, dest_st_fn)
    unwind_and_size(src_rewrite_ctx, dest_rewrite_ctx)
    dest_rewrite_ctx.pages.close()
    dest_rewrite_ctx.pages = utils.doutf(opts, dest_st_fn, 'r+b')
    return (src_rewrite_ctx, dest_rewrite_ctx)
