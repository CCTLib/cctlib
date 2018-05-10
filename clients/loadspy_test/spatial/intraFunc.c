#include <stdio.h>

int a[100]={1,1,2,2,3,3,4,4,5,5};
int sum;

void main() {
    for (int i = 0; i < 5000000; i++)
        for (int j = 0; j < 10; j++)
            sum += a[j];

    printf("%d\n", sum);
}
