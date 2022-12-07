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

#define EUSAGE 1
#define EDIR 2
#define ENOENTRY 3
#define EBUFF 4
#define EAPI 5

typedef unsigned long address;


struct tracee_thread_info {
    pid_t tid; //thread id
    pid_t pid; //pid
    address *eq_points; //equivalence points
};


typedef struct tracee_thread_info thread_info;


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
    else
        log_error("Undefined error. Err no: %d", errno);
}


int main(int argc, char **argv)
{
    int err = 0;
    int i;
    pid_t pid;
    pid_t thread_ids[MAX_THREADS];
    char bin_path[MAX_STRING];
    size_t num_threads;
    ssize_t ret;

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

exit:
    print_error_code(err);
    return 0;
}
