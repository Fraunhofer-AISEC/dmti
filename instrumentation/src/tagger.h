#ifndef TAGGER_H
#define TAGGER_H 1

#include <stdio.h>
#include <unistd.h>
#include <sys/auxv.h>

#ifndef MTE_GRANULARITY
#define MTE_GRANULARITY 16
#endif

#define TAG_MASK 0xFUL
#define TAG_SHIFT 56
#define CLEAR_TAG(x) ((void *)(((unsigned long)x) & ~(TAG_MASK << TAG_SHIFT)))
#define GET_TAG(x) (((unsigned long)x) & (TAG_MASK << TAG_SHIFT))

/*
 * Insert a random logical tag into the given pointer.
 */
#define insert_random_tag(ptr) ({ \
        uint64_t __val;           \
        asm("irg %0, %1"          \
            : "=r"(__val)         \
            : "r"(ptr));          \
        __val;                    \
})

/*
 * Get the allocation tag of the source address.
 */
#define get_tag(addr) ({            \
        void *__val;                \
        asm volatile("ldg %0, [%1]" \
                     : "=r"(__val)  \
                     : "r"(addr)    \
                     : "memory");   \
        __val;                      \
})

/*
 * Set the allocation tag on the destination address.
 */
#define set_tag(tagged_addr)                    \
        do                                      \
        {                                       \
                asm volatile("stg %0, [%0]"     \
                             :                  \
                             : "r"(tagged_addr) \
                             : "memory");       \
        } while (0)

/*
 * Set the allocation tag on the destination address for 2 TGs (2 * 16 Byte).
 */
#define set_2tag(tagged_addr)                   \
        do                                      \
        {                                       \
                asm volatile("st2g %0, [%0]"    \
                             :                  \
                             : "r"(tagged_addr) \
                             : "memory");       \
        } while (0)

/*
 * Set the allocation tag on the destination address and clear the data (set it to zero).
 */
#define zero_set_tag(tagged_addr)               \
        do                                      \
        {                                       \
                asm volatile("stzg %0, [%0]"    \
                             :                  \
                             : "r"(tagged_addr) \
                             : "memory");       \
        } while (0)

/*
 * Set the allocation tag on the destination address for 2 TGs and clear the data (set it to zero).
 */
#define zero_set_2tag(tagged_addr)              \
        do                                      \
        {                                       \
                asm volatile("stz2g %0, [%0]"   \
                             :                  \
                             : "r"(tagged_addr) \
                             : "memory");       \
        } while (0)

void *tag_ptr_mem(void *ptr, size_t size);

void tag_mem(unsigned long address, size_t size);

void *zero_ptr_tag_mem(void *ptr, size_t size);

void zero_tag_mem(unsigned long address, size_t size);

#endif // TAGGER_H