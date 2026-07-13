// Compile: aarch64-linux-gnu-g++ -march=armv8.5-a+memtag heap.c -o heap -g
// Run: qemu-aarch64 -L /usr/aarch64-linux-gnu ./heap
#include <stdlib.h>
#include <stdio.h>

#define SIZE 14

void f(char *a, int i) {
    if (i >= SIZE) {
        printf("Expecting SIGSEGV...\n");
    }
    printf("a = %p; a[%d] = %d\n", a, i, a[i]);
}

int main() {
    char a[SIZE] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 
    };
    f(a, 16);
    
    return 0;
}