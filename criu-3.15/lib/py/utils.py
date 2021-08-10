import os
import struct
import sys

def get_bin_file_symbols(nm, dir, bin):
    stream = os.popen(nm + ' ' + os.path.join(dir, bin) + " -n | grep 'T'")
    output = stream.read()
    stream.close()
    return output


def print_stack(sp, bp, ip, pages, pages_to_skip, funcs, adr, st_vaddr):
    print('\nbp: 0x%lx' % bp)
    i = len(adr) - 1
    if ip:
        print('ip: 0x%lx (%s + %d)' % (ip, funcs[i], ip - adr[-1]))
    temp = bp
    pages.seek(((pages_to_skip) << 12) + (bp - st_vaddr))
    bp = struct.unpack('<Q', pages.read(8))[0]
    ip = struct.unpack('<Q', pages.read(8))[0]
    print('(RBP + 0x8) 0x%lx (%ld)' % (ip, ip))
    print('(RBP + 0x0) 0x%lx (%ld)' % (bp, bp))
    pages.seek(((pages_to_skip) << 12) + (sp - st_vaddr))
    ba = []
    diff = temp - sp
    for _ in range(diff/8):
        ba.append(struct.unpack('<Q', pages.read(8))[0])
    j = 1
    for i in range(len(ba)-1, 1, -1):
        print('(RBP - 0x%x) 0x%lx (%ld)' % (j*8, ba[i], ba[i]))
        j += 1
    sp = temp
    return (sp, bp, ip)


def inf(opts):
    if opts['in']:
        return open(opts['in'], 'rb')
    else:
        return sys.stdin


def outf(opts):
    if opts['out']:
        return open(opts['out'], 'w+')
    else:
        return sys.stdout


def dinf(opts, name):
    return open(os.path.join(opts['dir'], name), 'rb')


def doutf(opts, name):
    return open(os.path.join(opts['dir'], name), 'wb')