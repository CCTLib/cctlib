/* This test is the simplest one */

#include <stdio.h>
#include <sys/time.h>

#define MAX 5010


void shashawen(int index)
{
   int a,b,c,d,e,f;
   int i,j;
   int array[2];

   for(i = 0;i < 2; ++i){
       a = b + c;
       d = b;
       e = c;
       f = e + d;
       array[i] = index;
   }
}

void main()
{
   int test[MAX];
   int i;
   struct timeval start,end;
   gettimeofday(&start,NULL);

   for(i = 0; i < MAX; ++i)
       shashawen(test[i]);
   gettimeofday(&end,NULL);
   printf("%lf s used\n",(end.tv_sec-start.tv_sec)*1000+(double)(end.tv_usec-start.tv_usec)/1000);
}
