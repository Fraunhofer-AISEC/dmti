// Compile: aarch64-linux-gnu-g++ -march=armv8.5-a+memtag heap.c -o heap -g
// Run: qemu-aarch64 -L /usr/aarch64-linux-gnu ./heap
#include <stdlib.h>
#include <stdio.h>

#define FULL 0
#define SIZE 14

void f(char *a, int i) {
    if (i >= (SIZE/16 + 1) * 16) {
        printf("Expecting SIGSEGV...\n");
    }
    a[i] = i; // maby cause write overflow
    printf("a = %p; a[%d] = %d\n", a, i, a[i]);
}

int main() {
    char a[SIZE] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 
    };
    for(int i = 0; i < SIZE; i++) {
        f(a, i);
    }
    // Uncatched Out of bounds read due to granularity
    f(a, 14);
    // Expected SIGSEGV due to MTE missmatch (if correctly instrumented)
    f(a, -1);
    
    return 0;
}