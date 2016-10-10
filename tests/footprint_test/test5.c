#include <stdio.h>
#define N (10000000)
int A[N];
int B[N/2];

void g()
{
  int i=0;
  int t1, t2;
  for (i = 0; i<N; i+=5) t1 = A[i];
  for (i = 0; i<N; i+=5) t2 = A[i];
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
