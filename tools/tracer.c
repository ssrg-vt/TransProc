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
#ifdef __x86_64__
#include <sys/reg.h>
#endif
#include <sys/user.h>
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
 * Attempts to attach to threads.
 *
 * thread_id: pointer to buffer containing thread ids to attach to.
 * entries: number of threads in the buffer.
 *
 * return: error code.
 */
int attach_to_threads(pid_t *thread_id, size_t entries)
{
    int i;
    long ret;
    for(i = 0; i < entries; i++) {
        while(1) {
            ret = ptrace(PTRACE_ATTACH, thread_id[i], NULL, NULL);
            if(ret == -1L && (errno == ESRCH || errno == EBUSY || \
                        errno == EFAULT)) {
                sched_yield();
                continue;
            }
            break;
        }
        if(ret == -1L) {
            for(int j = 0; j < i; j++) {
                while(1) {
                    ret = ptrace(PTRACE_DETACH, thread_id[j], NULL, NULL);
                    if( ret == -1L && (errno == ESRCH || errno == EBUSY || \
                                errno == EFAULT)) {
                        sched_yield();
                        continue;
                    }
                    break;
                }
            }
            return -ENOTSUP;
        }
    }
    return 0;
}


/*
 * Attempts to detach from threads.
 *
 * thread_id: pointer to buffer containing thread ids to detach from.
 * entries: num of threads in the buffer.
 *
 * return: error code.
 */
int detach_from_threads(pid_t *thread_id, size_t entries)
{
    int i;
    long ret;

    for(i = 0; i < entries; i++) {
        while(1) {
            ret = ptrace(PTRACE_DETACH, thread_id[i], NULL, NULL);
            if(ret == -1L && (errno == ESRCH || errno == EBUSY || errno == EFAULT)) {
                sched_yield();
                continue;
            }
            break;
        }
        if(ret == -1L)
            return -ENOTSUP;
    }
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


long get_symbol_addr(const char *bin_path, const char *symbol)
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
                    return sym_tbl[j].st_value;
            }
        }
    }
   
    return -1;
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
    long symbol_addr;
};


long get_regs(pid_t cpid, struct user_regs_struct *regs)
{
    long r;
#ifdef __x86_64__
    r = ptrace(PTRACE_GETREGS, cpid, 0, regs);
#endif
#ifdef __aarch64__
    r = ptrace(PTRACE_GETREGSET, cpid, 0, regs);
#endif
    return r;   
}


void *trace_thread(void *argp)
{
    long err, data, symbol_addr;
    pid_t thread_id;
    struct user_regs_struct regs;
    int wait_status;

    struct tracee_info *info = (struct tracee_info *)argp;

    thread_id = info->thread_id;
    symbol_addr = info->symbol_addr;

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
    }

#ifdef __x86_64__
    log_info("Thread %d: RIP = 0x%08llu", thread_id, regs.rip);
    log_info("Thread %d: RBP = 0x%08llu", thread_id, regs.rbp);
#endif
#ifdef __aarch64__
    log_info("Thread %d: PC = 0x%08llu", thread_id, regs.regs[30]);
    log_info("Thread %d: BP = 0x%08llu", thread_id, regs.regs[29]);
#endif

    /*
    err = ptrace(PTRACE_SINGLESTEP, thread_id, NULL, NULL);
    if(err < 0){
        log_error("Thread %d: single step %d failed", thread_id, i);
    }
    else{
        log_info("Thread %d: single step %d successful", thread_id, i);
    }
    */

    /*
    err = ptrace(PTRACE_DETACH, thread_id, NULL, NULL);
    if(ptrace < 0) {
        log_error("PTRACE_DETACH failed for thread: %d", thread_id);
    }
    log_info("Thread %d detached", thread_id);
    */
    return NULL;
}


int main(int argc, char **argv)
{
    int i;
    size_t num_threads;
    ssize_t ret;
    pid_t thread_id[MAX_THREADS];
    char bin_path[MAX_STRING];
    long symbol_addr;
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

    
    /*
    err = attach_to_threads(thread_id, num_threads);
    if(err){
        log_error("Could not attach to all threads!");
        return -1;
    }
    log_info("Attached to all threads!");
    */ 
    
    ret = get_binary_path(pid, bin_path, MAX_STRING);
    log_info("Binary path found: %s", bin_path);

    
    symbol_addr = get_symbol_addr(bin_path, INDICATOR);
    if(symbol_addr <= 0) {
        log_error("Error finding symbol %s address", INDICATOR);
    }
    else
        log_info("Symbol %s address: 0x%08lx", INDICATOR, symbol_addr); 

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


    /*
    long data = ptrace(PTRACE_PEEKDATA, pid, symbol_addr, NULL);
    log_info("Data: %ld", data);

    data = 10;

    long r =  ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
    if(r < 0) {
        log_error("Could not interrupt");
    } 
    */

    data = 1;

    ptrace(PTRACE_POKEDATA, pid, symbol_addr, (void *)data); 
    log_info("Putting value %ld", data);

    data = ptrace(PTRACE_PEEKDATA, pid, symbol_addr, NULL);
    log_info("Read data: %ld", data);

    r = ptrace(PTRACE_DETACH, pid, NULL, NULL);
    if(r < 0)
        log_error("PTRACE_DETACH failed");
    else
        log_info("PTRACE_DETACH successful");

    /*
    err = detach_from_threads(thread_id, num_threads);
    if(err){
        log_error("Could not detach from all threads!");
        return -1;
    }
    log_info("Detached from all threads");
    */
    
    for(i=0; i<num_threads; i++) {
        info[i].thread_id = thread_id[i];
        info[i].symbol_addr = symbol_addr;

        pthread_create(&threads[i], NULL, trace_thread, (void *)&info[i]);
    }

    for(i=0; i <num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
