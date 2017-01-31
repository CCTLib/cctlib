/* This test is for arrays */

#include <stdio.h>

int a[1000];

void array(){

    int i,j;
    for(i=0;i<1000;++i)
       a[i] = 10;
    int b;
    for(i=0;i<3;++i)
       b = a[2];
    printf("b is %d\n",b);
    printf("a[0] at %p\n",&a[0]);
    printf("a[1] at %p\n",&a[1]);
}

void main(){
    array();
}
