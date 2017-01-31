// @COPYRIGHT@
// Licensed under MIT license.
// See LICENSE.TXT file in the project root for more information.
// ==============================================================

#define N (0xfffff)

int a[N];

void Foo() {
    int i;

    for(i = 0 ; i < N ; i++) a[i] = 0;
}
void Bar() {
    int i;

    for(i = 0 ; i < N ; i++) a[i] = 0;
}

int main() {
    Foo();
    Bar();
    Foo();
    return 0;
}
