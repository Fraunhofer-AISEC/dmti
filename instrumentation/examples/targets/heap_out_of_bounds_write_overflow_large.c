// Compile: aarch64-linux-gnu-g++ -march=armv8.5-a+memtag heap.c -o heap -g
// Run: qemu-aarch64 -L /usr/aarch64-linux-gnu ./heap
#include <stdlib.h>
#include <stdio.h>

int main() {
    char *a = (char *)malloc(65530);
    
    printf("a = %p\n", a);
    a[0] = 0;
    a[13] = 13;
    // Uncatched Out of bounds read due to granularity
    a[65530] = 14;
    // Expected SIGSEGV due to MTE missmatch (if correctly instrumented)
    printf("Expecting SIGSEGV...\n");
    a[65536] = 15;
    
    free(a);
    
    return 0;
}