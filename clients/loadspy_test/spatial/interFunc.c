#include <stdio.h>

int a[1000000]={1};
int sum;

void test(int i) {
    sum += a[i];
}

void main() {
    for (int i = 0; i < 1000000; i++)
        test(i);
    
    printf("%d\n", sum);
}
