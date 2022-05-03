#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include "migrate.h"

int pid_main;

void func2(int i)
{
    printf("[%d] Executing %s on: ", i, __func__);
    fflush(stdout);
    system("uname -m");
}

void func1(int i)
{
    printf("[%d] Executing %s on: ", i, __func__);
    fflush(stdout);
    system("uname -m");
    func2(i);
    sleep(2);
}

int main(int argc, char *argv[])
{
    int i=0;

    pid_main = getpid();
    printf("pid: %d.\n", pid_main);

    while (1) {
        func1(++i);
    }
    return 0;
}
