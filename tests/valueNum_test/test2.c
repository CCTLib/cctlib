/* This is the test for div instructions */

#include <stdio.h>

#define MAX 5010

int devide(int num, int divider){

    int result = num/divider;
    int a , b ,c, d, i;
    double e, f, g, h;

    for(i=0;i < MAX; ++i){
       a = 10;
       b = 5;
       c = a/b;
       d = 5;
       a = d/a;
       e = 20.23;
       f = 10.12;
       g = e/f;
       h = e;
       f = f/h;
    }

    return result;
}


void main(){
   devide(1,2);
}
