#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <signal.h>
#include <syscall.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>

void procmsg(const char *format, ...)
{
    va_list ap;
    fprintf(stdout, "[%d] ", getpid());
    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);
}

void run_target(const char *programname)
{
    procmsg("target started. will run '%s'\n", programname);

    /* Allow tracing of this process */
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
    {
        perror("ptrace");
        return;
    }

    /* Replace this process's image with the given program */
    execl(programname, programname, (char *)NULL);
}

void get_regs(pid_t cpid, struct user_regs_struct *regs)
{
    ptrace(PTRACE_GETREGS, cpid, 0, regs);
}

unsigned long set_breakpoint(pid_t cpid, unsigned long addr)
{
    // unsigned long addr = 0x00501031;
    unsigned long data = ptrace(PTRACE_PEEKTEXT, cpid, (void *)addr, 0);

    // Write the trap instruction
    #ifdef __aarch64__
        unsigned long trap = 0xd4200000;
    #endif
    #ifdef __x86_64__
        unsigned long trap = (data & 0xFFFFFF00) | 0xCC;
    #endif
    ptrace(PTRACE_POKETEXT, cpid, (void *)addr, (void *)trap);

    return data;
}

void suspend(pid_t cpid)
{
    if (kill(cpid, SIGSTOP) != 0)
    {
        perror("sigstop");
    }
}

void remove_breakpoint(pid_t cpid, unsigned long addr, unsigned long data, struct user_regs_struct *regs)
{
    /* Remove the breakpoint by restoring the previous data
     * at the target address, and unwind the RIP back by 1 to
     * let the CPU execute the original instruction.
     */
    ptrace(PTRACE_POKETEXT, cpid, (void *)addr, (void *)data);
    #ifdef __aarch64__
        regs->pc -= 1;
    #endif
    #ifdef __x86_64__
        regs->rip -= 1;
    #endif
    ptrace(PTRACE_SETREGS, cpid, 0, regs);
}

void continue_running(pid_t cpid)
{
    // Let the child process continue running
    ptrace(PTRACE_CONT, cpid, 0, 0);
}

void wait_child()
{
    int wait_status;
    wait(&wait_status);
    if (WIFSTOPPED(wait_status))
    {
        procmsg("Child got a signal: %s\n", strsignal(WSTOPSIG(wait_status)));
    }
    else
    {
        perror("wait");
        return;
    }
}

void run_debugger(pid_t cpid, unsigned long addr)
{
    struct user_regs_struct regs;

    procmsg("debugger started\n");

    // Wait for child to stop on its first instruction
    wait_child();

    // Obtain and show child's RIP reg
    get_regs(cpid, &regs);
    
    #ifdef __aarch64__
        procmsg("Child started at PC = 0x%08x\n", regs.pc);
    #endif
    #ifdef __x86_64__
        procmsg("Child started at RIP = 0x%08x\n", regs.rip);
    #endif

    unsigned long data = set_breakpoint(cpid, addr);

    continue_running(cpid);

    wait_child();

    // Obtain and show child's RIP reg
    get_regs(cpid, &regs);

    #ifdef __aarch64__
        procmsg("Child stopped at PC = 0x%08x\n", regs.pc);
    #endif
    #ifdef __x86_64__
        procmsg("Child stopped at RIP = 0x%08x\n", regs.rip);
    #endif

    remove_breakpoint(cpid, addr, data, &regs);

    suspend(cpid);
}

int main(int argc, char **argv)
{
    pid_t cpid;

    #ifdef __aarch64__
        procmsg("Target arch: aarch64\n");
    #endif
    #ifdef __x86_64__
        procmsg("Target arch: x86_64\n");
    #endif

    if (argc < 3)
    {
        fprintf(stderr, "Expected a program name and address as arguments.\n");
        return -1;
    }
    unsigned long addr = strtoul(argv[2], NULL, 16);
    cpid = fork();
    if (cpid == 0)
        run_target(argv[1]);
    else if (cpid > 0)
        run_debugger(cpid, addr);
    else
    {
        perror("fork");
        return -1;
    }

    return 0;
}
