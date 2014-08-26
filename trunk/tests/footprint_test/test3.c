#include <stdio.h>
#define N (10000000)
int A[N];
int B[N/2];
int C[N];

void g()
{
  int i=0;
  for (i = 0; i<N; i++) A[i] ++;
  for (i = 0; i<N; i++) C[i] ++;
}

void h()
{
  int i;
  for (i = 0; i<N/2; i++) B[i]++;
}

void f()
{
  g();
}

int main()
{
  f();
  h();
  return 0;
}
