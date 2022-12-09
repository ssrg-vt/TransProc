/*
 * Copyright (c) Abhishek Bapat. SSRG, Virginia Tech.
 * abapat28@vt.edu
 */

#include <string.h>
#include <sys/ptrace.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <sched.h>
#include <elf.h>
#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include "log.h"

#define MAX_THREADS 64
#define MAX_STRING 1024

#define CS_ADDR ".stack_transform.addr"

#define EUSAGE 1
#define EDIR 2
#define ENOENTRY 3
#define EBUFF 4
#define EAPI 5
#define EFILE 6
#define EMEM 7


typedef unsigned long address;


struct tracee_thread_info {
    pid_t tid; //thread id
    pid_t pid; //pid
    size_t num_threads;
};


typedef struct tracee_thread_info thread_info;

struct call_site { 
    unsigned long long id;
    unsigned long long addr;
    unsigned int frame_size;
    unsigned short num_unwind;
    unsigned long long unwind_offset;
    unsigned short num_live;
    unsigned long long live_offset;
    unsigned short num_arch_live;
    unsigned long long arch_live_offset;
    unsigned short padding;
} __attribute__ ((packed));


int get_thread_ids(pid_t *thread_ids, size_t *entries, pid_t pid, \
        size_t max_size)
{
    char dir_name[MAX_STRING];
    DIR *dir;
    struct dirent *entry;
    int tid, e;
    int max_threads;
    char d;

    *entries = 0;
    e = 0;

    max_threads = max_size/sizeof(pid_t);

    if (snprintf(dir_name, sizeof(dir_name), "/proc/%d/task/", (int)pid) \
            >= sizeof(dir_name))
        return -EBUFF;

    dir = opendir(dir_name);
    if (!dir)
        return -ENOENTRY;

    while(1) {
        entry = readdir(dir);

        if(!entry)
            break;

        if(e >= max_threads)
            break;

        if(sscanf(entry->d_name, "%d%c", &tid, &d) != 1)
            continue;

        thread_ids[e++] = (pid_t)tid;
    }

    *entries = e;

    if(closedir(dir))
        return -EDIR;

    return 0;
}


ssize_t get_binary_path(pid_t pid, char *buffer, size_t max_size)
{
    ssize_t ret;
    char link_path[MAX_STRING];
    char temp_path[MAX_STRING];

    if(snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid) \
            >= sizeof(link_path))
        return -EBUFF;

    ret = readlink(link_path, temp_path, MAX_STRING);
    if(ret <= 0)
        return -EAPI;
    if(ret >= max_size)
        return -EBUFF;

    temp_path[ret] = '\0';

    sprintf(buffer, "%s", temp_path);

    return ret+1;
}


void read_elf_header(int fd, Elf32_Ehdr *elf_header)
{
    assert(elf_header != NULL);
    assert(lseek(fd, (off_t)0, SEEK_SET) == (off_t)0);
    assert(read(fd, (void *)elf_header, sizeof(Elf32_Ehdr)) == sizeof(Elf32_Ehdr));
}


void read_elf_header64(int fd, Elf64_Ehdr *elf_header)
{
    assert(elf_header != NULL);
    assert(lseek(fd, (off_t)0, SEEK_SET) == (off_t)0);
    assert(read(fd, (void *)elf_header, sizeof(Elf64_Ehdr)) == sizeof(Elf64_Ehdr));
}


int is_elf(Elf32_Ehdr eh)
{
    if(!strncmp((char*)eh.e_ident, "\177ELF", 4)) {
        /* IS a ELF file */
        return 1;
    } else {
        /* Not ELF file */
        return 0;
    }
}


int is64_bit(Elf32_Ehdr eh) {
    if(eh.e_ident[EI_CLASS] == ELFCLASS64)
        return 1;
    else
        return 0;
}


void read_section_header_table64(int fd, Elf64_Ehdr eh, Elf64_Shdr *sh_table)
{
    int i;

    assert(lseek(fd, (off_t)eh.e_shoff, SEEK_SET) == (off_t)eh.e_shoff);

    for(i = 0; i < eh.e_shnum; i++) {
        assert(read(fd, (void *)&sh_table[i], eh.e_shentsize) \
                == eh.e_shentsize);
    }
}


char * read_section64(int32_t fd, Elf64_Shdr sh)
{
    char* buff = malloc(sh.sh_size);
    if(!buff) {
        log_error("%s:Failed to allocate %ldbytes\n",
                __func__, sh.sh_size);
    }

    assert(buff != NULL);
    assert(lseek(fd, (off_t)sh.sh_offset, SEEK_SET) == (off_t)sh.sh_offset);
    assert(read(fd, (void *)buff, sh.sh_size) == sh.sh_size);

    return buff;
}


unsigned long set_breakpoint(pid_t pid, unsigned long addr)
{
    unsigned long data, trap;
    data = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, 0);

#ifdef __x86_64__
    trap = (data & 0xFFFFFF00) | 0xCC;
#endif
#ifdef __aarch64__
    trap = 0xd4200000;
#endif

    ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)trap);

    return data;
}


void remove_breakpoint(pid_t pid, unsigned long addr, unsigned long data)
{
    ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)data);
}

void update_regs(pid_t pid, struct user_regs_struct *regs)
{
    struct iovec io;

    io.iov_base = regs;
    io.iov_len = sizeof(struct user_regs_struct);

#ifdef __x86_64__
    regs->rip -= 1;
#endif
#ifdef __aarch64__
    regs->pc -= 4;
#endif

    ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, (void *)&io);
}


long get_regs(pid_t cpid, struct user_regs_struct *regs)
{
    long r;
    struct iovec io;
    io.iov_base = regs;
    io.iov_len = sizeof(struct user_regs_struct);
    r = ptrace(PTRACE_GETREGSET, cpid, (void *)NT_PRSTATUS, (void *)&io);
    return r;
}


long set_regs(pid_t pid, struct user_regs_struct *regs)
{
    long r;
    struct iovec io;
    io.iov_base = regs;
    io.iov_len = sizeof(struct user_regs_struct);
    r = ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, (void *)&io);
    return r;
}


void print_error_code(int err)
{
    if(err == 0)
        log_info("Successful execution. Err No: %d", errno);
    else if(err == -EUSAGE)
        log_error("Usage error. Err no: %d", errno);
    else if(err == EDIR)
        log_error("Error calling dir api. Err No: %d", errno);
    else if(err == ENOENTRY)
        log_error("Entry not found. Err No: %d", errno);
    else if(err == EBUFF)
        log_error("Buffer not large enough. Err No: %d", errno);
    else if(err == EAPI)
        log_error("Error calling some API. Err No: %d", errno);
    else if(err == EFILE)
        log_error("Error handling a file. Err No: %d", errno);
    else if(err == EMEM)
        log_error("Error handling memory. Err No: %d", errno);
    else
        log_error("Undefined error. Err no: %d", errno);
}


int get_eq_point_addresses(const char *bin_path, unsigned long **addrs, \
        unsigned int *num_entries)
{
    Elf32_Ehdr eh;
    Elf64_Ehdr eh64;
    int fd;
    Elf64_Shdr *sh_tbl;
    int i, err=0;
    char *str_tbl;
    unsigned int str_tbl_idx;
    struct call_site *sh_cs;
    unsigned long sh_cs_size;
    unsigned long *addr;
    unsigned int entries;

    fd = open(bin_path, O_RDONLY|O_SYNC);
    if(fd < 0) {
        log_error("Unable to open file %s", bin_path);
        err = -EFILE;
        goto exit;
    }

    read_elf_header(fd, &eh);
    if(!is_elf(eh)) {
        log_error("File %s is not an ELF file", bin_path);
        err = -EFILE;
        goto exit;
    }

    if(!is64_bit(eh)) {
        log_error("Only 64-bit ELF files supported!");
        err = -EFILE;
        goto exit;
    }

    read_elf_header64(fd, &eh64);

    sh_tbl = malloc(eh64.e_shentsize * eh64.e_shnum);
    if(!sh_tbl) {
        log_error("Could not allocate memory for section header table");
        err = -EMEM;
        goto exit;
    }

    read_section_header_table64(fd, eh64, sh_tbl);

    for(i = 0; i < eh64.e_shnum; i++) {
        if(sh_tbl[i].sh_type == SHT_STRTAB) {
            str_tbl = read_section64(fd, sh_tbl[i]);
        }
    }

    if(!str_tbl) {
        log_error("Could not find string table");
        err = -EAPI;
        goto exit;
    }

    for(i = 0; i < eh64.e_shnum; i++) {
        //log_debug("Section %d: %s", i, str_tbl + sh_tbl[i].sh_name);
        if(strcmp((str_tbl + sh_tbl[i].sh_name), CS_ADDR) == 0){
            log_info("Section holding addresses of equivalence points found!");
            sh_cs_size = sh_tbl[i].sh_size;
            sh_cs = (struct call_site *)read_section64(fd, sh_tbl[i]);
            break;
        }
    }

    entries = sh_cs_size/sizeof(struct call_site);
    addr = malloc(sizeof(unsigned long)*(entries));
    if(!addr) {
        log_error("Could not allocate memory for storing addresses");
        err = -EMEM;
        goto exit;
    }

    for(i = 0; i < sh_cs_size / sizeof(struct call_site); i++) {
        addr[i] = sh_cs[i].addr;
        //log_debug("Address found: 0x%lx", addr[i]);
    }

    *addrs = addr;
    *num_entries = entries;

exit:
    if (!sh_tbl)
        free(sh_tbl);
    
    if(!str_tbl)
        free(str_tbl);

    if(!sh_cs)
        free(sh_cs);

    return err;
}


int main(int argc, char **argv)
{
    int err = 0;
    int i, wait_status;
    pid_t pid;
    pid_t thread_ids[MAX_THREADS];
    char bin_path[MAX_STRING];
    size_t num_threads;
    ssize_t ret;
    unsigned long *eq_point_addrs;
    unsigned long *original_instructions;
    unsigned int num_addrs;
    struct user_regs_struct regs;

    if (argc != 2) {
        log_error("Usage: %s [pid]", argv[0]);
        err = -EUSAGE;
        goto exit;
    }

    pid = strtoul(argv[1], NULL, 10); //TODO: Verify PID exists

    err = get_thread_ids(thread_ids, &num_threads, pid, \
            sizeof(pid_t)*MAX_THREADS);
    if(err){
        log_error("Error getting thread ids for process %d", pid);
        goto exit;
    }

    for(i = 0; i < num_threads; i++) {
        log_info("Thread %d has id: %d", i+1, thread_ids[i]);
    }


    ret = get_binary_path(pid, bin_path, MAX_STRING);
    if(ret <= 0) {
        log_error("Error finding binary path");
        err = (int)ret;
        goto exit;
    }
    log_info("Binary path found: %s", bin_path);

    err = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if(err < 0) {
        log_error("PTRACE_ATTACH failed");
        err = -EAPI;
        goto exit;
    }

    waitpid(pid, &wait_status, 0);
    if(WIFSTOPPED(wait_status))
        log_info("Process %d got a signal: %s", pid, strsignal(WSTOPSIG(wait_status)));
    else
        log_error("Wait");

    err = get_eq_point_addresses(bin_path, &eq_point_addrs, &num_addrs);
    log_info("Equivalence points found!");

    original_instructions = malloc(sizeof(unsigned long)*num_addrs);
    if(!original_instructions) {
        log_error("Could not allocate memory for original instructions");
        err = -EMEM;
        goto exit;
    }

    for(i = 0; i < num_addrs; i++){
        original_instructions[i] = set_breakpoint(pid, eq_point_addrs[i]);
    }
    log_info("Breakpoints inserted");

    err = ptrace(PTRACE_CONT, pid, NULL, NULL);
    if(err < 0)
        log_error("PTRACE_CONT failed");
    else
        log_info("PTRACE_CONT successful");

    waitpid(pid, &wait_status, 0);
    log_info("Thread %d got signal %s", pid, strsignal(WSTOPSIG(wait_status)));

    err = get_regs(pid, &regs);
    if(err < 0) {
        log_error("Thread %d: failed to get register value", pid);
        err = -EAPI;
        goto exit;
    }

    for(i = 0; i < num_addrs; i++) {
        remove_breakpoint(pid, eq_point_addrs[i], original_instructions[i]);
    }
    log_info("Breakpoints removed");

    update_regs(pid, &regs);

     if(kill(pid, SIGSTOP) != 0) {
        log_error("Cannot SIGSTOP");
        err = -EAPI;
        goto exit;
    }

exit:
    if(eq_point_addrs != NULL)
        free(eq_point_addrs);

    if(original_instructions != NULL)
        free(original_instructions);

    print_error_code(err);
    return 0;
}
