#include<stdlib.h>
#include<math.h>
#include<stdio.h>

void Foo(){
        int j =0 ;
        while( j ++ < 0xff){
                int i;
                int sz = 0xffff;
                int * a = malloc(sz * sizeof(int));
        //fprintf(stderr, "\n a = %p \n", a);
                int * b = calloc(sz * sizeof(int), 1);
        //fprintf(stderr, "\n b = %p \n", b);
                int * c = malloc(sz * sizeof(int));
        //fprintf(stderr, "\n c = %p \n", c);
                int * d = malloc(sz * sizeof(int));
        //fprintf(stderr, "\n d = %p \n", d);
                int * e = realloc(a, (sz + 100) * sizeof(int));
        //fprintf(stderr, "\n e = %p \n", e);
                for (i = 0 ; i < sz; i++)
                        d[i] = c[i] = b[i] = e[i] = 0;
                free(e);
                free(b);
                free(c);
                free(d);
        }
}


int main(){
        fprintf(stderr, "\n APP STARTED \n");
        #pragma omp parallel 
        {
                Foo();
        }
        return 0;
}

