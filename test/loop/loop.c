#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

void func_path_a(int cnt)
{
    int i = 0;
    printf("In function %s.\n", __func__);
    while(i < cnt) {
        sleep(5);
        printf("%d \n", ++i);
    }
    printf("Finish %s.\n", __func__);
}

void func_path_b(int cnt)
{
    printf("In function %s.\n", __func__);
    func_path_a(cnt);
    printf("Finish %s.\n", __func__);
}

/**
 * @brief Use ./multi_path -a | -b | -n <loop cnt>
 */
int main(int argc, char *argv[])
{
    int cnt = 5;
    int flags=2, opt;

    /**
     * @brief Simulate a multi-option program.
     */
    while ((opt = getopt(argc, argv, "abn:")) != -1) {
        switch (opt) {
        case 'a':
            flags = 1;
            break;
        case 'b':
            flags = 2;
            break;
        case 'n':
            cnt = atoi(optarg);
            break;
        default: /* '?' */
            fprintf(stderr, "Usage: %s [-n loop_cnt] [-a] [-b]\n",
                    argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    printf("pid: %d, cnt: %d \n", getpid(), cnt);

    if (flags == 1) func_path_a(cnt);
    if (flags == 2) func_path_b(cnt);

    printf("%s: Finish the loop...\n", __func__);
    return 0;
}
