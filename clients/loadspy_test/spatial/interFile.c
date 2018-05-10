#include <stdio.h>
#include"interFile.h"

int sum;

void main() {
    for (int i = 0; i < 1000000; i++)
        sum += test(i);
    printf("%d\n", sum);
}
