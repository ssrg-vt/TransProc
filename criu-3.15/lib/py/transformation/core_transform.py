import pycriu
import os

from . import definitions
from . import reg_x86_64
from . import reg_aarch64

def transform_core(src_ctx, dest_ctx, dest_core_fn, src_core, opts):
    update_mtype(dest_ctx, src_core)
    update_tc(opts, src_core)

def update_mtype(dest_ctx, src_core):
    if dest_ctx.st_handle.type == definitions.X86_64:
        src_core['entries'][0]['mtype'] = "X86_64"
    elif dest_ctx.st_handle.type == definitions.AARCH64:
        src_core['entries'][0]['mtype'] = "AARCH64"
    else:
        raise Exception("Destination arch type not supported.")
    
def update_tc(opts, src_core):
    #TODO: check rlimits
    src_core['entries'][0]['tc']['comm'] = os.path.join(opts['dir'], opts['dest'])

def update_thread_core(opts, src_core):
    src_core['entries'][0]['thread_core']['comm'] = os.path.join(opts['dir'], opts['dest'])

def update_thread_info(src_ctx, dest_ctx, src_core):
    #TODO: Check TLS
    #TODO: gpregs->pstate
    if src_ctx.st_handle.type == definitions.X86_64:
        ti = src_core['entries'][0]['thread_info']
        src_core['entries'][0].pop('thread_info')
    elif src_ctx.st_handle.type == definitions.AARCH64:
        ti = src_core['entries'][0]['ti_aarch64']
        src_core['entries'][0].pop('ti_aarch64')
    else:
        raise Exception("Source architecture not supported")
    if dest_ctx.st_handle.type == definitions.X86_64:
        ti_accessor = 'thread_info'
        src_core['entires'][0]['thread_info'] = ti
    elif dest_ctx.st_handle.type == definitions.AARCH64:
        ti_accessor = 'ti_aarch64'
        src_core['entries'][0]['ti_aarch64'] = ti
    else:
        raise Exception("Destination architecture not supported")
    
    