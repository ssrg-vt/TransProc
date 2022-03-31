#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <signal.h>
#include <syscall.h>
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
#include <string.h>
#include <sched.h>
#include <elf.h>
#include <assert.h>
#include <fcntl.h>
#include "log.h" 

#define MAX_THREADS 64
#define MAX_STRING 1024

#define INDICATOR "__indicator"
#define CHECK_MIGRATE "check_migrate"


struct symbol_addresses {
    long indicator_addr;
    long check_migrate_addr;
};


static pthread_mutex_t lock;
static volatile int flag = 0;
static volatile int trace_done = 0;

/*
 * Finds the thread ids of the given pid from the proc file system.
 *
 * thread_id: buffer which will be filled with thread ids.
 * pid: pid of the process whose thread ids are needed.
 * entries: buffer which will be filled with the number of returned entries.
 * max_size: max size in bytes which can be used in the thread_id buffer.
 *
 * returns: error code.
 */
int get_thread_ids(pid_t *thread_id, pid_t pid, size_t *entries, size_t max_size)
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
        return -ENOTSUP;

    dir = opendir(dir_name);
    if (!dir) 
        return -ENOENT;

    while(1) {
        entry = readdir(dir);
        
        if(!entry)
            break;

        if(e >= max_threads)
            break;

        if(sscanf(entry->d_name, "%d%c", &tid, &d) != 1)
            continue;

        if(tid < 1)
            continue;

        thread_id[e++] = (pid_t)tid;
    }

    *entries = e;

    if(closedir(dir))
        return -ENOTSUP;

    return 0;
}


/*
 * Attempts to the get the path of the binary which ran a process.
 *
 * pid: pid of the process.
 * buffer: vuffer to place the file in.
 * max_size: max number of characters that can be placed in the buffer.
 *
 * return: number of characters placed in the buffer.
 */
ssize_t get_binary_path(pid_t pid, char *buffer, size_t max_size)
{
    ssize_t ret;
    char link_path[MAX_STRING];
    char temp_path[MAX_STRING];

    if(snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid) \
            >= sizeof(link_path))
        return -1;

    ret = readlink(link_path, temp_path, MAX_STRING);
    if(ret <= 0)
        return ret;
    if(ret >= max_size)
        return -1;

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


int is_ELF(Elf32_Ehdr eh)
{
    if(!strncmp((char*)eh.e_ident, "\177ELF", 4)) {
        /* IS a ELF file */
        return 1;
    } else {
        /* Not ELF file */
        return 0;
    }
}


int is64Bit(Elf32_Ehdr eh) {                                                    
    if (eh.e_ident[EI_CLASS] == ELFCLASS64)                                      
        return 1;                                                             
    else                                                                                                                                         
        return 0;                                                            
}


void read_section_header_table64(int32_t fd, Elf64_Ehdr eh, Elf64_Shdr sh_table[])
{                                                                                
    uint32_t i;                                                                  
                                                                                 
    assert(lseek(fd, (off_t)eh.e_shoff, SEEK_SET) == (off_t)eh.e_shoff);         
                                                                                 
    for(i=0; i<eh.e_shnum; i++) {                                                
        assert(read(fd, (void *)&sh_table[i], eh.e_shentsize)                    
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


int get_symbol_addr(const char *bin_path, const char *symbol, \
        const char *symbol2, struct symbol_addresses *addrs)
{
    Elf32_Ehdr eh;
    Elf64_Ehdr eh64;
    Elf64_Shdr *sh_tbl;
    Elf64_Sym *sym_tbl;
    char *str_tbl;
    int fd, i, j, symbol_count;
    uint32_t str_tbl_ndx;

    fd = open(bin_path, O_RDONLY|O_SYNC);
    if(fd < 0) {
        log_error("Unable to open file %s", bin_path);
        return -1;
    }

    read_elf_header(fd, &eh);
    if(!is_ELF(eh)) {
        log_error("File %s is not an ELF file", bin_path);
        return -1;
    }

    if(!is64Bit(eh)) {
        log_error("Only 64-bit ELF files supported!");
        return -1;
    }

    read_elf_header64(fd, &eh64);

    sh_tbl = malloc(eh64.e_shentsize * eh64.e_shnum);
    if(!sh_tbl) {
        log_error("Coult not allocate memory for section header");
    }

    read_section_header_table64(fd, eh64, sh_tbl); 

    for(i = 0; i < eh64.e_shnum; i++) {
        if((sh_tbl[i].sh_type == SHT_SYMTAB) || \
                (sh_tbl[i].sh_type == SHT_DYNSYM)) {
            sym_tbl = (Elf64_Sym *)read_section64(fd, sh_tbl[i]);

            str_tbl_ndx = sh_tbl[i].sh_link;
            str_tbl = read_section64(fd, sh_tbl[str_tbl_ndx]);

            symbol_count = sh_tbl[i].sh_size/sizeof(Elf64_Sym);

            for(j = 0; j < symbol_count; j++) {
                if(strcmp((str_tbl + sym_tbl[j].st_name), symbol) == 0)
                    addrs->indicator_addr = sym_tbl[j].st_value;
                if(strcmp((str_tbl + sym_tbl[j].st_name), symbol2) == 0)
                    addrs->check_migrate_addr = sym_tbl[j].st_value;
            }
        }
    }
   
    return 0;
}


int wait_for_threads(pid_t *thread_id, size_t entries)
{
    int i, wait_status;

    for(i = 0; i < entries; i++) {
        waitpid(thread_id[i], &wait_status, 0);
        log_info("Thread %d: got signal: %s\n", thread_id[i], \
                strsignal(wait_status));
    }
    return 0;
}

struct tracee_info {
    pid_t thread_id;
    pid_t pid;
    long symbol_addr;
    int num_threads;
};


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

long set_breakpoint(pid_t pid, long addr)
{
    long data = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, 0);

    // Write trap instruction
#ifdef __x86_64__
    long trap = (data & 0xFFFFFF00) | 0xCC;
#endif
#ifdef __aarch64__
    long trap = 0xd4200000;
#endif
    ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)trap);
    log_info("Thread %d: breakpoint place at 0x%08lx", pid, addr);

    return data;
}


void remove_trap(pid_t pid, long addr)
{
    long d;
    d = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL);
#ifdef __x86_64__
    long data = (d & 0xFFFFFF00) | 0x90;
#endif
#ifdef __aarch64__
    long data = 0xe1a00000;
#endif
    ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)data);
}
    

void remove_breakpoint(pid_t cpid, unsigned long addr, unsigned long data, struct user_regs_struct *regs)
{
    ptrace(PTRACE_POKETEXT, cpid, (void *)addr, (void *)data);
     struct iovec io;
    io.iov_base = regs;
    io.iov_len = sizeof(struct user_regs_struct);
#ifdef __aarch64__
    regs->pc -= 1;
#endif
#ifdef __x86_64__
    regs->rip -= 1;
#endif
    ptrace(PTRACE_SETREGS, cpid, 0, regs);
}


void suspend(pid_t pid)
{
    if(kill(pid, SIGSTOP) != 0)
        log_error("SIGSTOP");
}


void *trace_thread(void *argp)
{
    long err, data, brk_addr, indicator_addr, instr, ret_add_loc, ret_addr;
    pid_t thread_id;
    pid_t pid;
    struct user_regs_struct regs;
    int wait_status, flag_local, trace_done_local, num_threads;

    flag_local = 0;
    trace_done_local = 0;

    struct tracee_info *info = (struct tracee_info *)argp;

    thread_id = info->thread_id;
    pid = info->pid;
    indicator_addr = info->symbol_addr;
    num_threads = info->num_threads;

    err = ptrace(PTRACE_SEIZE, thread_id, NULL, NULL);
    if(ptrace < 0) {
        log_error("PTRACE_SEIZE failed for thread: %d", thread_id);
        return NULL;
    }
    log_info("Thread %d seized", thread_id);

    waitpid(thread_id, &wait_status, 0);
    log_info("Thread %d: got signal %s", thread_id, \
            strsignal(WSTOPSIG(wait_status)));

    err = get_regs(thread_id, &regs);
    if(err < 0) {
        log_error("Thread %d: failed to get register value", thread_id);
        return NULL;
    }

#ifdef __x86_64__
    log_info("Thread %d: RIP = 0x%08llx", thread_id, regs.rip);
    log_info("Thread %d: RBP = 0x%08llx", thread_id, regs.rbp);
    ret_add_loc = regs.rbp + 8;
    regs.rip -= 1;
    brk_addr = regs.rip;
#endif
#ifdef __aarch64__
    log_info("Thread %d: PC = 0x%08llx", thread_id, regs.regs[30]);
    log_info("Thread %d: BP = 0x%08llx", thread_id, regs.regs[29]);
    ret_add_loc = regs.regs[29] + 8;
    regs.pc -= 4;
    brk_addr = regs.pc;
#endif

    ret_addr = ptrace(PTRACE_PEEKDATA, thread_id, (void *)ret_add_loc, NULL);       
    log_info("Thread %d: Value at BP+0x8: 0x%08lx", thread_id, ret_addr);

    /* main thread */
    if(pid == thread_id) {
        data = -1;
        instr = ptrace(PTRACE_PEEKTEXT, thread_id, brk_addr, NULL);
        log_info("Thread %d: addr: 0x%08lx opcode 0x%08lx", thread_id, \
                brk_addr, instr);
        remove_trap(pid, brk_addr);
        log_info("Thread %d: trap removed!", thread_id);
        err = ptrace(PTRACE_POKEDATA, pid, indicator_addr, (void *)data);
        if(err < 0) {
            log_error("Thread %d: could not restore indicator value!", thread_id);
            return NULL;
        }
        log_info("Thread %d: indicator value restored!", thread_id);
        pthread_mutex_lock(&lock);
        flag = 1;
        pthread_mutex_unlock(&lock);
    }

    while(flag_local == 0) {
        sched_yield();
        pthread_mutex_lock(&lock);
        flag_local = flag;
        pthread_mutex_unlock(&lock);
    }

    err = set_regs(thread_id, &regs);
    if(err < 0) {
        log_error("Thread %d: failed to set register values", thread_id);
        return NULL;
    }
    log_info("Thread %d: instruction pointer updated!", thread_id);

    pthread_mutex_lock(&lock);
    data = set_breakpoint(thread_id, ret_addr);

    err = ptrace(PTRACE_CONT, thread_id, NULL, NULL);
    if (err < 0){
        log_error("Thread %d: PTRACE_CONT failed", thread_id);
        return NULL;
        pthread_mutex_unlock(&lock);
    }
    log_info("Thread %d: continuing", thread_id);
    
    waitpid(thread_id, &wait_status, 0);
    log_info("Thread %d: got signal %s", thread_id, \
            strsignal(WSTOPSIG(wait_status)));

    err = get_regs(thread_id, &regs);     
    if(err < 0) {
        log_error("Thread %d: get regs failed", thread_id);
        pthread_mutex_unlock(&lock);
        return NULL;
    }

    remove_breakpoint(thread_id, ret_addr, data, &regs);
    log_info("Thread %d: breakpoint removed", thread_id);

    trace_done += 1;
    pthread_mutex_unlock(&lock);

    while(trace_done_local < num_threads) {
        sched_yield();
        pthread_mutex_lock(&lock);
        trace_done_local = trace_done;
        pthread_mutex_unlock(&lock);
    }

    log_info("Thread %d: all tracee threads processed!", thread_id);

    while((pid != thread_id) && flag_local == 1) {
        sched_yield();
        pthread_mutex_lock(&lock);
        flag_local = flag;
        pthread_mutex_unlock(&lock);
    }

    if(pid != thread_id)
        return NULL;

    suspend(pid);

    log_info("Thread %d: process suspended", thread_id);

    pthread_mutex_lock(&lock);
    flag = 0;
    pthread_mutex_unlock(&lock);

    return NULL;
}


int main(int argc, char **argv)
{
    int i;
    size_t num_threads;
    ssize_t ret;
    pid_t thread_id[MAX_THREADS];
    char bin_path[MAX_STRING];
    struct symbol_addresses sa; 
    long data, r;
    struct tracee_info info[MAX_THREADS];
    pid_t pid;
    pthread_t threads[MAX_THREADS];
    int err, wait_status;

    if(argc != 2) {
        log_error("Usage: %s [pid]", argv[0]);
        return -1;
    }

    pid = strtoul(argv[1], NULL, 10);

    err = get_thread_ids(thread_id, pid, &num_threads, sizeof(pid_t)*MAX_THREADS);
    if(err)
        log_error("Error getting thread ids for process %d", pid);

    for(i = 0; i < num_threads; i++) {
        log_info("Thread %d has id: %d", i+1, thread_id[i]);
    }

    ret = get_binary_path(pid, bin_path, MAX_STRING);
    log_info("Binary path found: %s", bin_path);

    
    err  = get_symbol_addr(bin_path, INDICATOR, CHECK_MIGRATE, &sa);
    if(err < 0) {
        log_error("Error finding symbol %s address", INDICATOR);
        return -1;
    }
    else {
        log_info("Symbol %s address: 0x%08lx", INDICATOR, sa.indicator_addr); 
        log_info("Symbol %s address: 0x%08lx", CHECK_MIGRATE, sa.check_migrate_addr);
    }

    r = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    if(r < 0) {
        log_error("PTRACE_ATTACH failed");
        return -1;
    }
    log_info("PTRACE_ATTACH successful!");

    waitpid(pid, &wait_status, 0);
    if(WIFSTOPPED(wait_status))
        log_info("Process %d got a signal: %s", pid, strsignal(WSTOPSIG(wait_status)));
    else
        log_error("Wait");

    data = 1;

    ptrace(PTRACE_POKEDATA, pid, sa.indicator_addr, (void *)data); 
    log_info("Putting value %ld", data);

    data = ptrace(PTRACE_PEEKDATA, pid, sa.indicator_addr, NULL);
    log_info("Read data: %ld", data);

    r = ptrace(PTRACE_DETACH, pid, NULL, NULL);
    if(r < 0)
        log_error("PTRACE_DETACH failed");
    else
        log_info("PTRACE_DETACH successful");

    pthread_mutex_init(&lock, NULL);

    for(i=0; i<num_threads; i++) {
        info[i].thread_id = thread_id[i];
        info[i].pid = pid;
        info[i].symbol_addr = sa.indicator_addr;
        info[i].num_threads = num_threads;

        pthread_create(&threads[i], NULL, trace_thread, (void *)&info[i]);
    }

    for(i=0; i <num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    pthread_mutex_destroy(&lock);

    return 0;
}
