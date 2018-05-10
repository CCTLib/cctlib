#ifndef __INTERFILE__
#define __INTERFILE__

int a[10]={1,2,3,4,5,6,7,8,9,10};

int test() {
    int sum = 0;
    for (int i = 0; i < 10; i++)
        sum += a[i];
    return sum;
}

#endif
