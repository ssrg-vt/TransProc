#include <stdio.h>
#include <string.h>
#include <stdlib.h>


struct information {
    int num1;
    long num2;
    unsigned long num3;
};


int change_values(struct information *info){
    info->num1 = 100;
    info->num2 = 200;
    info->num3 = 300;
    return 0;
}


int main(int argc, char *argv[]) {
    struct information *info;
    info = (struct information *)malloc(sizeof(struct information));
    if(!info)
        return -1;
    info->num1 = 1;
    info->num2 = 2;
    info->num3 = 3;
    printf("Before: %d, %ld, %lu \n", info->num1, info->num2, info->num3);
    change_values(info);
    printf("After: %d, %ld, %lu \n", info->num1, info->num2, info->num3);
    return 0;
}
