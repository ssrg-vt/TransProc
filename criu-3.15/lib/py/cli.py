from __future__ import print_function
import struct
from jsonpath_ng import parse

import argparse
import sys
import json
import os

import pycriu

from pycriu import stack_map_utils
from pycriu import elf_utils
from pycriu import utils
from pycriu.converter import Aarch64Converter, X8664Converter


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


def dinf(opts, name, mode=None):
    if not mode:
        return open(os.path.join(opts['dir'], name))
    else:
        return open(os.path.join(opts['dir'], name), mode)


def edit(opts):
    indent = None
    try:
        img = pycriu.images.load(inf(opts), opts['pretty'], opts['nopl'])
    except pycriu.images.MagicException as exc:
        print("Unknown magic %#x.\n"
              "Maybe you are feeding me an image with "
              "raw data(i.e. pages.img)?" % exc.magic, file=sys.stderr)
        sys.exit(1)

    if opts['pretty']:
        indent = 4
    f = outf(opts)
    while True:
        j = json.dumps(img, indent=indent)
        f.write(j)
        f.write("\n")
        f.write("Provide JSONPath for node to update or leave blank to exit.\n")
        ans = sys.stdin.readline().rstrip()
        if ans == '':
            break
        j_expr = parse(ans)
        j_expr.find(img)
        f.write("Provide value to write.\n")
        val = sys.stdin.readline().rstrip()
        if str(val).isnumeric():
            val = int(val)
        j_expr.update(img, val)
    pycriu.images.dump(img, open(opts['in'], 'wb'))


def decode(opts):
    indent = None

    try:
        img = pycriu.images.load(inf(opts), opts['pretty'], opts['nopl'])
    except pycriu.images.MagicException as exc:
        print("Unknown magic %#x.\n"\
          "Maybe you are feeding me an image with "\
          "raw data(i.e. pages.img)?" % exc.magic, file=sys.stderr)
        sys.exit(1)

    if opts['pretty']:
        indent = 4

    f = outf(opts)
    json.dump(img, f, indent=indent)
    if f == sys.stdout:
        f.write("\n")


def encode(opts):
    img = json.load(inf(opts))
    pycriu.images.dump(img, outf(opts))


def info(opts):
    infs = pycriu.images.info(inf(opts))
    json.dump(infs, sys.stdout, indent=4)
    print()


def get_task_id(p, val):
    return p[val] if val in p else p['ns_' + val][0]


#
# Explorers
#


class ps_item:
    def __init__(self, p, core):
        self.pid = get_task_id(p, 'pid')
        self.ppid = p['ppid']
        self.p = p
        self.core = core
        self.kids = []


def show_ps(p, opts, depth=0):
    print("%7d%7d%7d   %s%s" %
          (p.pid, get_task_id(p.p, 'pgid'), get_task_id(p.p, 'sid'), ' ' *
           (4 * depth), p.core['tc']['comm']))
    for kid in p.kids:
        show_ps(kid, opts, depth + 1)


def explore_ps(opts):
    pss = {}
    ps_img = pycriu.images.load(dinf(opts, 'pstree.img'))
    for p in ps_img['entries']:
        core = pycriu.images.load(
            dinf(opts, 'core-%d.img' % get_task_id(p, 'pid')))
        ps = ps_item(p, core['entries'][0])
        pss[ps.pid] = ps

    # Build tree
    psr = None
    for pid in pss:
        p = pss[pid]
        if p.ppid == 0:
            psr = p
            continue

        pp = pss[p.ppid]
        pp.kids.append(p)

    print("%7s%7s%7s   %s" % ('PID', 'PGID', 'SID', 'COMM'))
    show_ps(psr, opts)


files_img = None


def ftype_find_in_files(opts, ft, fid):
    global files_img

    if files_img is None:
        try:
            files_img = pycriu.images.load(dinf(opts, "files.img"))['entries']
        except:
            files_img = []

    if len(files_img) == 0:
        return None

    for f in files_img:
        if f['id'] == fid:
            return f

    return None


def ftype_find_in_image(opts, ft, fid, img):
    f = ftype_find_in_files(opts, ft, fid)
    if f:
        return f[ft['field']]

    if ft['img'] == None:
        ft['img'] = pycriu.images.load(dinf(opts, img))['entries']
    for f in ft['img']:
        if f['id'] == fid:
            return f
    return None


def ftype_reg(opts, ft, fid):
    rf = ftype_find_in_image(opts, ft, fid, 'reg-files.img')
    return rf and rf['name'] or 'unknown path'


def ftype_pipe(opts, ft, fid):
    p = ftype_find_in_image(opts, ft, fid, 'pipes.img')
    return p and 'pipe[%d]' % p['pipe_id'] or 'pipe[?]'


def ftype_unix(opts, ft, fid):
    ux = ftype_find_in_image(opts, ft, fid, 'unixsk.img')
    if not ux:
        return 'unix[?]'

    n = ux['name'] and ' %s' % ux['name'] or ''
    return 'unix[%d (%d)%s]' % (ux['ino'], ux['peer'], n)


file_types = {
    'REG': {
        'get': ftype_reg,
        'img': None,
        'field': 'reg'
    },
    'PIPE': {
        'get': ftype_pipe,
        'img': None,
        'field': 'pipe'
    },
    'UNIXSK': {
        'get': ftype_unix,
        'img': None,
        'field': 'usk'
    },
}


def ftype_gen(opts, ft, fid):
    return '%s.%d' % (ft['typ'], fid)


files_cache = {}


def get_file_str(opts, fd):
    key = (fd['type'], fd['id'])
    f = files_cache.get(key, None)
    if not f:
        ft = file_types.get(fd['type'], {'get': ftype_gen, 'typ': fd['type']})
        f = ft['get'](opts, ft, fd['id'])
        files_cache[key] = f

    return f


def explore_fds(opts):
    ps_img = pycriu.images.load(dinf(opts, 'pstree.img'))
    for p in ps_img['entries']:
        pid = get_task_id(p, 'pid')
        idi = pycriu.images.load(dinf(opts, 'ids-%s.img' % pid))
        fdt = idi['entries'][0]['files_id']
        fdi = pycriu.images.load(dinf(opts, 'fdinfo-%d.img' % fdt))

        print("%d" % pid)
        for fd in fdi['entries']:
            print("\t%7d: %s" % (fd['fd'], get_file_str(opts, fd)))

        fdi = pycriu.images.load(dinf(opts, 'fs-%d.img' % pid))['entries'][0]
        print("\t%7s: %s" %
              ('cwd', get_file_str(opts, {
                  'type': 'REG',
                  'id': fdi['cwd_id']
              })))
        print("\t%7s: %s" %
              ('root', get_file_str(opts, {
                  'type': 'REG',
                  'id': fdi['root_id']
              })))


class vma_id:
    def __init__(self):
        self.__ids = {}
        self.__last = 1

    def get(self, iid):
        ret = self.__ids.get(iid, None)
        if not ret:
            ret = self.__last
            self.__last += 1
            self.__ids[iid] = ret

        return ret


def explore_mems(opts):
    ps_img = pycriu.images.load(dinf(opts, 'pstree.img'))
    vids = vma_id()
    for p in ps_img['entries']:
        pid = get_task_id(p, 'pid')
        mmi = pycriu.images.load(dinf(opts, 'mm-%d.img' % pid))['entries'][0]

        print("%d" % pid)
        print("\t%-36s    %s" % ('exe',
                                 get_file_str(opts, {
                                     'type': 'REG',
                                     'id': mmi['exe_file_id']
                                 })))

        for vma in mmi['vmas']:
            st = vma['status']
            if st & (1 << 10):
                fn = ' ' + 'ips[%lx]' % vids.get(vma['shmid'])
            elif st & (1 << 8):
                fn = ' ' + 'shmem[%lx]' % vids.get(vma['shmid'])
            elif st & (1 << 11):
                fn = ' ' + 'packet[%lx]' % vids.get(vma['shmid'])
            elif st & ((1 << 6) | (1 << 7)):
                fn = ' ' + get_file_str(opts, {
                    'type': 'REG',
                    'id': vma['shmid']
                })
                if vma['pgoff']:
                    fn += ' + %#lx' % vma['pgoff']
                if st & (1 << 7):
                    fn += ' (s)'
            elif st & (1 << 1):
                fn = ' [stack]'
            elif st & (1 << 2):
                fn = ' [vsyscall]'
            elif st & (1 << 3):
                fn = ' [vdso]'
            elif vma['flags'] & 0x0100:  # growsdown
                fn = ' [stack?]'
            else:
                fn = ''

            if not st & (1 << 0):
                fn += ' *'

            prot = vma['prot'] & 0x1 and 'r' or '-'
            prot += vma['prot'] & 0x2 and 'w' or '-'
            prot += vma['prot'] & 0x4 and 'x' or '-'

            astr = '%08lx-%08lx' % (vma['start'], vma['end'])
            print("\t%-36s%s%s" % (astr, prot, fn))


def explore_rss(opts):
    ps_img = pycriu.images.load(dinf(opts, 'pstree.img'))
    for p in ps_img['entries']:
        pid = get_task_id(p, 'pid')
        vmas = pycriu.images.load(dinf(opts, 'mm-%d.img' %
                                       pid))['entries'][0]['vmas']
        pms = pycriu.images.load(dinf(opts, 'pagemap-%d.img' % pid))['entries']

        print("%d" % pid)
        vmi = 0
        pvmi = -1
        for pm in pms[1:]:
            pstr = '\t%lx / %-8d' % (pm['vaddr'], pm['nr_pages'])
            while vmas[vmi]['end'] <= pm['vaddr']:
                vmi += 1

            pme = pm['vaddr'] + (pm['nr_pages'] << 12)
            vstr = ''
            while vmas[vmi]['start'] < pme:
                vma = vmas[vmi]
                if vmi == pvmi:
                    vstr += ' ~'
                else:
                    vstr += ' %08lx / %-8d' % (
                        vma['start'], (vma['end'] - vma['start']) >> 12)
                    if vma['status'] & ((1 << 6) | (1 << 7)):
                        vstr += ' ' + get_file_str(opts, {
                            'type': 'REG',
                            'id': vma['shmid']
                        })
                    pvmi = vmi
                vstr += '\n\t%23s' % ''
                vmi += 1

            vmi -= 1

            print('%-24s%s' % (pstr, vstr))


explorers = {
    'ps': explore_ps,
    'fds': explore_fds,
    'mems': explore_mems,
    'rss': explore_rss
}


def dump_stackmap_data(opts):
    elffile = elf_utils.open_elf_file(opts['dir'], opts['bin'])
    section = elf_utils.get_elf_section(
        elffile, stack_map_utils.STACKMAP_SECTION)
    print("Reading section: " + section.name)
    stack_maps = stack_map_utils.parse_stack_maps(section)
    stack_map_utils.print_stack_map_data(stack_maps)


def dump_sections(opts):
    elffile = elf_utils.open_elf_file(opts['dir'], opts['bin'])
    sections = elf_utils.get_elf_section(elffile)
    for s in sections:
        print(s.name)


def dump_section_unwind_addr(opts):
    elffile = elf_utils.open_elf_file(opts['dir'], opts['bin'])
    section = elf_utils.get_elf_section(
        elffile, stack_map_utils.UNWIND_ADDR_SECTION)
    entries = elf_utils.get_num_entries(section)
    if entries > 0:
        unwind_addrs = stack_map_utils.parse_unwind_addrs(section, True)


def dump_section_unwind_loc(opts):
    elffile = elf_utils.open_elf_file(opts['dir'], opts['bin'])
    section = elf_utils.get_elf_section(
        elffile, stack_map_utils.UNWIND_SECTION)
    entries = elf_utils.get_num_entries(section)
    if entries > 0:
        unwind_locs = stack_map_utils.parse_unwind_locs(section, True)


def dump_section_cs_id(opts):
    elffile = elf_utils.open_elf_file(opts['dir'], opts['bin'])
    section = elf_utils.get_elf_section(elffile, stack_map_utils.ID_SECTION)
    entries = elf_utils.get_num_entries(section)
    if entries > 0:
        call_sites = stack_map_utils.parse_call_sites_by_id(section, True)


def dump_section_cs_addr(opts):
    elffile = elf_utils.open_elf_file(opts['dir'], opts['bin'])
    section = elf_utils.get_elf_section(elffile, stack_map_utils.ADDR_SECTION)
    entries = elf_utils.get_num_entries(section)
    if entries > 0:
        call_sites = stack_map_utils.parse_call_sites_by_addr(section, True)


def dump_section_live_vals(opts):
    elffile = elf_utils.open_elf_file(opts['dir'], opts['bin'])
    section = elf_utils.get_elf_section(
        elffile, stack_map_utils.LIVE_VALUE_SECTION)
    entries = elf_utils.get_num_entries(section)
    if entries > 0:
        live_vals = stack_map_utils.parse_live_values(section, entries, True)


def dump_section_arch_live_vals(opts):
    elffile = elf_utils.open_elf_file(opts['dir'], opts['bin'])
    section = elf_utils.get_elf_section(
        elffile, stack_map_utils.ARCH_LIVE_SECTION)
    entries = elf_utils.get_num_entries(section)
    if entries > 0:
        arch_live_vals = stack_map_utils.parse_arch_live_values(
            section, entries, True)


def explore(opts):
    explorers[opts['what']](opts)


sm_utils = {
    'dump_sm': dump_stackmap_data,
    'dump_sections': dump_sections,
    'dump_sec_unw_addr': dump_section_unwind_addr,
    'dump_sec_unw_loc': dump_section_unwind_loc,
    'dump_sec_cs_id': dump_section_cs_id,
    'dump_sec_cs_addr': dump_section_cs_addr,
    'dump_sec_live_val': dump_section_live_vals,
    'dump_sec_arch_live': dump_section_arch_live_vals
}


def elf(opts):
    sm_utils[opts['what']](opts)

def sunw(opts):
    ps_img = pycriu.images.load(utils.dinf(opts, 'pstree.img'))
    proc_num = 1
    output = utils.get_bin_file_symbols(opts['nm'], opts['dir'], opts['bin'])
    if output == '':
        print('Error parsing symbols from obj file.\n')
        return
    temp = [v.split(' ')[0] for v in output.split('\n')]
    addresses = [int(a, 16) for a in temp if a != '']
    funcs = [v.split(' ')[2] for v in output.split('\n') if v != '']
    for p in ps_img['entries']:
        pid = get_task_id(p, 'pid')
        tids = p['threads']
        for tid in tids:
            print("\nFor core-%d" % tid)
            core = pycriu.images.load(
                utils.dinf(opts, 'core-%d.img' % tid))['entries'][0]
            if core['mtype'] == 'X86_64':
                sp = core['thread_info']['gpregs']['sp']
                bp = core['thread_info']['gpregs']['bp']
                ip = core['thread_info']['gpregs']['ip']
            elif core['mtype'] == 'AARCH64':
                sp = core['ti_aarch64']['gpregs']['sp']
                bp = core['ti_aarch64']['gpregs']['regs'][29]
                ip = core['ti_aarch64']['gpregs']['pc']
            pms = pycriu.images.load(utils.dinf(
                opts, 'pagemap-%d.img' % pid))['entries']
            pages_to_skip = 0
            for pm in pms[1:]:
                nr_pages = pm['nr_pages']
                st_vaddr = pm['vaddr']
                end_vaddr = st_vaddr + (nr_pages << 12)
                if(sp > end_vaddr):
                    pages_to_skip += nr_pages
                    continue
                else:
                    break

            print('sp: 0x%lx' % sp)
            pages = utils.dinf(opts, "pages-%d.img" % proc_num)
            if sp != bp:
                pages.seek(((pages_to_skip) << 12) + (sp - st_vaddr))
                for i in range(2):
                    val = struct.unpack('<Q', pages.read(8))[0]
                    print('(SP + 0x%x) 0x%lx (%ld)' % (8*i, val, val))

            while True:
                adr = [a for a in addresses if a <= ip]
                if not bp or bp <= st_vaddr:
                    break
                sp, bp, ip = utils.print_stack(
                    sp, bp, ip, pages, pages_to_skip, funcs, adr, st_vaddr)
            if ip:
                adr = [a for a in addresses if a <= ip]
                print('\nip: 0x%lx (%s + %d)' %
                    (ip, funcs[len(adr)-1], ip - adr[-1]))


def recode(opts):
    # copy appropriate binaries to dest path
    # transform all files
    # transform stack and regs
    debug = False
    if(opts['debug'] == 'y' or opts['debug'] == 'Y'):
        debug = True
    if opts['target'] == "aarch64":
        converter = Aarch64Converter(opts['src_dir'], opts['dest_dir'], 
            opts['src_bin'], opts['bin_dir'], debug)
    elif opts['target'] == 'x86-64':
        converter = X8664Converter(opts['src_dir'], opts['dest_dir'], 
            opts['src_bin'], opts['bin_dir'], debug)
    else:
        raise Exception('Architecture not supported')
    converter.assert_conditions()
    converter.recode()


def vdso_init(opts):
    ps = pycriu.images.load(dinf(opts, 'pstree.img', 'rb'))['entries'][0]
    pid = get_task_id(ps, 'pid')
    mm = pycriu.images.load(dinf(opts, "mm-%d.img" % pid, 'rb'))['entries'][0]
    core = pycriu.images.load(dinf(opts, 'core-%d.img' % pid, 'rb'))['entries'][0]
    vmas = mm['vmas']
    vdso = [v for v in vmas if (v['status']>>3)&1 != 0][0]
    vdso_st_addr = vdso['start']
    pm = pycriu.images.load(dinf(opts, 'pagemap-%d.img' % pid, 'rb'))['entries']
    pages_to_skip = 0
    for entry in pm[1:]:
        nr_pages = entry['nr_pages']
        if entry['vaddr'] != vdso_st_addr:
            pages_to_skip += nr_pages
        else:
            vdso_nr_pages = nr_pages 
            break
    
    pages = dinf(opts, "pages-%d.img" % 1, 'r+b')
    pages.seek(pages_to_skip<<12)
    if(not vdso_nr_pages):
        raise Exception("Could not find VDSO")
    
    vdso_num_bytes = vdso_nr_pages << 12
    vdso_bytes = pages.read(vdso_num_bytes)
    dir_path = os.path.dirname(os.path.realpath(__file__))
    if core['mtype'] == "X86_64":
        vdso_path = os.path.join(dir_path, "templates/", "x86_64_vdso.img.tmpl")
    elif core['mtype'] == "AARCH64":
        vdso_path = os.path.join(dir_path, "templates/", "aarch64_vdso.img.tmpl")
    else:
        raise Exception("Architecture not supported")
    f = open(vdso_path, 'wb')
    f.write(vdso_bytes)
    f.close()


def main():
    desc = 'CRiu Image Tool'
    parser = argparse.ArgumentParser(
        description=desc, formatter_class=argparse.RawTextHelpFormatter)

    subparsers = parser.add_subparsers(
        help='Use crit CMD --help for command-specific help')

    # Edit
    edit_parser = subparsers.add_parser(
        'edit', help="edit any criu image in human-readable (json) format")
    edit_parser.add_argument("in", help='criu image file to edit')
    edit_parser.add_argument('--nopl',
                             help='do not show entry payload (if exists)',
                             action='store_true')
    edit_parser.set_defaults(func=edit, pretty=True, out=None)

    # Decode
    decode_parser = subparsers.add_parser(
        'decode', help='convert criu image from binary type to json')
    decode_parser.add_argument(
        '--pretty',
        help=
        'Multiline with indents and some numerical fields in field-specific format',
        action='store_true')
    decode_parser.add_argument(
        '-i',
        '--in',
        help='criu image in binary format to be decoded (stdin by default)')
    decode_parser.add_argument(
        '-o',
        '--out',
        help='where to put criu image in json format (stdout by default)')
    decode_parser.set_defaults(func=decode, nopl=False)

    # Encode
    encode_parser = subparsers.add_parser(
        'encode', help='convert criu image from json type to binary')
    encode_parser.add_argument(
        '-i',
        '--in',
        help='criu image in json format to be encoded (stdin by default)')
    encode_parser.add_argument(
        '-o',
        '--out',
        help='where to put criu image in binary format (stdout by default)')
    encode_parser.set_defaults(func=encode)

    # Info
    info_parser = subparsers.add_parser('info', help='show info about image')
    info_parser.add_argument("in")
    info_parser.set_defaults(func=info)

    # Explore
    x_parser = subparsers.add_parser('x', help='explore image dir')
    x_parser.add_argument('dir')
    x_parser.add_argument('what', choices=['ps', 'fds', 'mems', 'rss'])
    x_parser.set_defaults(func=explore)

    # Show
    show_parser = subparsers.add_parser(
        'show', help="convert criu image from binary to human-readable json")
    show_parser.add_argument("in")
    show_parser.add_argument('--nopl',
                             help='do not show entry payload (if exists)',
                             action='store_true')
    show_parser.set_defaults(func=decode, pretty=True, out=None)

    # ELF Utils
    sm_parser = subparsers.add_parser('elf', help='elf utils')
    sm_parser.add_argument('dir', help='directory where image files exist')
    sm_parser.add_argument('what', 
        choices=[
            'dump_sm', 
            'dump_sections', 
            'dump_sec_unw_addr', 
            'dump_sec_unw_loc', 
            'dump_sec_cs_id',
            'dump_sec_cs_addr', 
            'dump_sec_live_val', 
            'dump_sec_arch_live'
        ]
    )
    sm_parser.add_argument('bin', help='binary file name')
    sm_parser.set_defaults(func=elf)

    # VSDO Init
    v_parser = subparsers.add_parser('vdso_init', help='initialize VDSO')
    v_parser.add_argument('dir', help='directory where image files exist')
    v_parser.set_defaults(func=vdso_init)

    # Stack Unwind
    sunw_parser = subparsers.add_parser(
        'sunw', help='unwind stack from image files')
    sunw_parser.add_argument('dir', help='directory where image files exist')
    sunw_parser.add_argument('nm', help='GNU util nm')
    sunw_parser.add_argument('bin', help='binary file name')
    sunw_parser.set_defaults(func=sunw)

    # Recode
    recode_parser = subparsers.add_parser('recode', 
        help='convert criu images from architecture A to architecture B')
    recode_parser.add_argument('src_dir', help='directory containing the images')
    recode_parser.add_argument('dest_dir', help='desired output directory')
    recode_parser.add_argument('target', 
        choices=['x86-64', 'aarch64'], help='target architecture')
    recode_parser.add_argument('src_bin', help='source binary file name')
    recode_parser.add_argument('bin_dir', help='bin directory')
    recode_parser.add_argument('debug', help='run in debug mode(y/n)')
    recode_parser.set_defaults(func=recode)
    

    opts = vars(parser.parse_args())

    if not opts:
        sys.stderr.write(parser.format_usage())
        sys.stderr.write("crit: error: too few arguments\n")
        sys.exit(1)

    opts["func"](opts)


if __name__ == '__main__':
    main()
