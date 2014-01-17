#define N (0xfffff)

int a[N];

int Foo() {
    int i;

    for(i = 0 ; i < N ; i++) a[i] = 0;
}
int Bar() {
    int i;

    for(i = 0 ; i < N ; i++) a[i] = 0;
}

int main() {
    Foo();
    Bar();
    Foo();
    return 0;
}
