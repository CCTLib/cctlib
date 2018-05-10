#include <stdio.h>

int a[10]={1,2,3,4,5,6,7,8,9,10};
int b[10]={10,12,32,4,5,6,7,8,92,10};
int sum;

void test2() {
    for (int l = 0; l < 10; l++)
        sum += b[l]; 
}

    
void test1() {
    for (int j = 0; j < 1000; j++)
        for (int k = 0; k < 10; k++) {
            sum += a[k];
            test2();
        }
}

void main() {
    for (int i = 0; i < 100; i++)
        test1();

    printf("%d\n", sum);
}
