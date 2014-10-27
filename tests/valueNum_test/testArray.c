/* This test is for arrays */

#include <stdio.h>

void array(){
    int a[10];
    int i,j;
    for(i=0;i<10;++i)
       for(j=0;j<5010;++j)
          a[i] = 10;
}

void main(){
    array();
}
