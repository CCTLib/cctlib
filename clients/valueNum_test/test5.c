/* This test is for multiple movs and multiplications */

#include <stdio.h>

#define MAX 5010


int test5(int a){
   int x, y, z;
   int b, c, d, e;
   int i = 0;

   for(i = 0; i < MAX; ++i){
       y = x;
       z = 3 + x;
       z = x;
       y = z;
       b = a * x - c * y;
       d = y * a;
       e = c;
       e = x * e;
   }
   return z;
}

void main(){
   test5(2);
}
