/* This test is for bit shifting operations */

#include <stdio.h>

#define MAX 5010

int logical(int a , int b){

   int c, d, e, f, g, h;
   unsigned long long cc, dd;
   unsigned long ee, ff;
   int i;

   for(i = 0; i < MAX; ++i){
      c = a & b;
      cc = (unsigned long long)c;
      ee = cc >> 32;
      ff = cc << 32;
      ee = (unsigned long)c;
      dd = ee | ff;
   }
   if( cc == dd)
      printf("cc and dd is the same!\n");
   return c;
}

void main(){
   logical(1,2);
}

