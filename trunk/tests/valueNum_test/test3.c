/* This test is for mixed redundancy */

#include <stdio.h>

#define MAX 5010

int mix(int a, int b){

    int c, d, e, f;
    int i;
    
    for(i=0;i<MAX;++i){
        c = a * b + d;
        e = a * b;
        f = e + d;
    }
    return f;
}


void main(){

    mix(1,2);

}
