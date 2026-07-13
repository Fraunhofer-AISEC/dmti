// Compile: aarch64-linux-gnu-g++ -march=armv8.5-a+memtag heap.c -o heap -g
// Run: qemu-aarch64 -L /usr/aarch64-linux-gnu ./heap
#include <stdlib.h>
#include <stdio.h>

int main() {
    // 2^16 - 6
    char *a = (char *)malloc(65530);
    
    printf("a = %p\n", a);
    printf("a[0] = %d\n", a[0]);
    printf("a[13] = %d\n", a[13]);
    // Uncatched Out of bounds read due to granularity
    printf("a[14] = %d\n", a[65535]);
    // Expected SIGSEGV due to MTE missmatch (if correctly instrumented)
    printf("Expecting SIGSEGV...\n"); // 2^16
    printf("a[16] = %d\n", a[65536]);
    
    free(a);
    
    return 0;
}