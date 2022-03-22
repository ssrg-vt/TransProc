#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/syscall.h>

void* func_path_a(void* cnt)
{
    int i = 0;
    printf("In function %s.\n", __func__);
    printf("pid: %d, cnt: %d \n", gettid(),*(int*)cnt);
    while(i < *(int*)cnt) {
        sleep(5);
        printf("%d: %d \n", gettid(), ++i);
    }
    printf("Finish %s.\n", __func__);

    return NULL;
}

void* func_path_b(void* cnt)
{
    printf("In function %s.\n", __func__);    
    printf("pid: %d, cnt: %d \n", gettid(), *(int*)cnt);
    func_path_a(cnt);
    printf("Finish %s.\n", __func__);

    return NULL;
}

/**
 * @brief Use ./multi_path -a | -b | -n <loop cnt>
 */
int main(int argc, char *argv[])
{
    int cnt = 5;
    int flags = 0;
    int opt = 0;
    pthread_t t1, t2;

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

    pthread_create(&t1, NULL, func_path_a, &cnt);
    pthread_create(&t2, NULL, func_path_b, &cnt);

    pthread_join(t1,NULL);
    pthread_join(t2,NULL);

    func_path_b((int*)&cnt);
    printf("%s: Finish the loop...\n", __func__);
    return 0;
}
