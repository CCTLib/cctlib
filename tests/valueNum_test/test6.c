#include <math.h>
int f(int a)
{
  int g = pow(a,0.75);
  return g;
}

int main()
{

  int a, b,c,d,e,f1;
  int i;
  for (i=0; i<10000; i++) {
    f(10);
    f(9);
  }
  return 0;
}
