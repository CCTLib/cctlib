#include <stdio.h>
#include"interFile.h"

int sum;

void main() {
    for (int i = 0; i < 100000; i++)
        sum += test();
    printf("%d\n", sum);
}
