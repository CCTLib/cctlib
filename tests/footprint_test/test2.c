#include <stdio.h>
#include <omp.h>

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

void f()
{
  g();
}

int main()
{
#pragma omp parallel num_threads(2)
{
#pragma omp sections
{
#pragma omp section
{
  f();
}
#pragma omp section
{
  h();
}
}
}
  return 0;
}
