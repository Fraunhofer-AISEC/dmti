#include "tagger.h"

size_t get_granules(size_t size)
{
    if (size <= 0)
    {
        return 0;
    }
    return (size - 1) / MTE_GRANULARITY + 1;
}

void *tag_ptr_mem(void *ptr, size_t size)
{
    unsigned long address = insert_random_tag((unsigned long)ptr);
    if (size > 0)
    {
        tag_mem(address, size);
    }

    return (void *)address;
}

void tag_mem(unsigned long address, size_t size)
{
    if (size <= 0)
    {
        return;
    }
    size_t granules = get_granules(size);
    int i = 0;
    if (granules % 2 != 0)
    {
        unsigned long offset = i * MTE_GRANULARITY;
#if DEBUG
        printf("Tagging [%lX - %lX[\n", address + offset, address + offset + 16);
#endif
        set_tag(address + offset);
        i++;
    }
    for (i; i < granules; i += 2)
    {
        unsigned long offset = i * MTE_GRANULARITY;
#if DEBUG
        printf("Tagging [%lX - %lX[\n", address + offset, address + offset + 2 * 16);
#endif
        set_2tag(address + offset);
    }
}

void *zero_ptr_tag_mem(void *ptr, size_t size)
{
    unsigned long address = insert_random_tag((unsigned long)ptr);
    if (size > 0)
    {
        zero_tag_mem(address, size);
    }
    return (void *)address;
}

void zero_tag_mem(unsigned long address, size_t size)
{
    if (size <= 0)
    {
        return;
    }
    size_t granules = get_granules(size);
    int i = 0;
    if (granules % 2 != 0)
    {
        unsigned long offset = i * MTE_GRANULARITY;
        zero_set_tag(address + offset);
        i++;
    }
    for (i; i < granules; i += 2)
    {
        unsigned long offset = i * MTE_GRANULARITY;
        zero_set_2tag(address + offset);
    }
}
