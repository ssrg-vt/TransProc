#include <stdio.h>
#include <pthread.h>
#include <unistd.h>

#define THREADS 5

void dummy(int tid)
{
    printf("Thread %d sleeping!\n", tid);
    sleep(1);
}

void *thread_func(void *argp)
{
    int thread_id;
    thread_id = *((int *)argp);
    while(1)
    {
        dummy(thread_id);
    }
    return NULL;
}

int main(void)
{
    pthread_t threads[THREADS];
    void *dummy;
    int thread_ids[THREADS];
    int tid = 0;
    for(int i = 1; i < THREADS; i++)
    {
        thread_ids[i] = i;
        pthread_create(&threads[i], NULL, thread_func, (void *)&thread_ids[i]);
    }

    dummy = thread_func((void *)&tid); 
    /*
    for(int i = 0; i < THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }
    */
    return 0;
}
