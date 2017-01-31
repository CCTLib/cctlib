#include <stdio.h>
#define N (10000000)
int A[N];
int B[N/2];

void g()
{
  int i=0;
  for (i = 0; i<N; i++) A[i] ++;
}

void h()
{
  int i;
  for (i = 0; i<N/2; i++) B[i]++;
}
void h1()
{
  int i;
  for (i = 1; i<N/2; i++) B[i] = B[i-1];
}

void f()
{
  g();
}

int main()
{
  f();
  h();
  h1();
  return 0;
}
