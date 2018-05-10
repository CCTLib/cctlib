#include <stdio.h>

int a[100]={1,2,3,4,5,6,7,8,9,10};
int b[100]={10,12,32,4,5,6,7,8,92,10};
int c[100]={1,-12,-2,4,-5,-6,7,8,9,-2};
int sum;

void main() {
    for (int i = 0; i < 100000; i++)
        for (int j = 0; j < 10; j++) {
            sum += a[j];
            for (int k = 0; k < 10; k++) { 
                sum += b[j];
                sum += c[k];
            }
        }

    printf("%d\n", sum);
}
