#include <stdio.h>
#define N (10000000)
int A[N];
int B[N/2];

void g()
{
  int i=0;
  for (i = 1; i<N; i++){
    A[i] = 2*B[i-1];
    B[i] = 0.5;
  }
}

void h1()
{
  int i;
  for (i = 1; i<N/2; i++) B[i] = B[i-1];
}

void f()
{
  int i;
  for (i = 1; i<N/2; i++) B[i-1] = B[i];
}

int main()
{
  f();
  g();
  h1();
  return 0;
}
