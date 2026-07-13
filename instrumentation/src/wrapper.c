#include "wrapper.h"

bool are_locks_init = false;
size_t malloc_size = 0;
size_t calloc_size = 0;
size_t alloca_size = 0;
size_t realloc_size = 0;
Tree *address_to_size = NULL;

size_t align(size_t val, size_t align)
{
    return ((val - 1) / align + 1) * align;
}

void insert_to_tree(void *address, size_t size)
{
    size_t *val = malloc(sizeof(size_t));
    *val = size;
    if (address_to_size == NULL)
    {
        address_to_size = create_node(NULL, (unsigned long)address, (void *)val);
    }
    else
    {
        insert(address_to_size, (unsigned long)address, (void *)val);
    }

#if DEBUG
    dr_printf("INFO: inserted: %p [%ld]\n", address, size);
#endif
}

void alloca_wrap_pre(void *wrapcxt, OUT void **user_data)
{
    alloca_size = (size_t)drwrap_get_arg(wrapcxt, 0);
#if DEBUG
    dr_printf("INFO: pre alloca wrap with param: %ld (0x%lx)\n", alloca_size, alloca_size);
#endif
    drwrap_set_arg(wrapcxt, 0, (void *)align(alloca_size, MTE_GRANULARITY));
}

void alloca_wrap_post(void *wrapcxt, void *user_data)
{
    void *return_address = drwrap_get_retval(wrapcxt);
    DR_ASSERT_MSG(
        return_address != NULL,
        "Alloca return NULL pointer");

    return_address = tag_ptr_mem(return_address, alloca_size);
    alloca_size = 0;
    DR_ASSERT_MSG(
        drwrap_set_retval(wrapcxt, return_address),
        "Cannot tag result pointer of alloca!");

#if DEBUG
    dr_printf("INFO: finished post alloca wrap with ptr: %p\n", return_address);
#endif
}

void malloc_wrap_pre(void *wrapcxt, OUT void **user_data)
{
    size_t loc_malloc_size = (size_t)drwrap_get_arg(wrapcxt, 0);
    malloc_size = align(loc_malloc_size, MTE_GRANULARITY);
#if DEBUG
    dr_printf("INFO: pre malloc wrap with param: %ld (0x%lx)\n", malloc_size, malloc_size);
#endif
    drwrap_set_arg(wrapcxt, 0, (void *)align(malloc_size, FRAME_SIZE));
}

void malloc_wrap_post(void *wrapcxt, void *user_data)
{
    DR_ASSERT(malloc_size >= 0);
    void *return_address = drwrap_get_retval(wrapcxt);
    DR_ASSERT_MSG(
        return_address != NULL,
        "Malloc return NULL pointer");
#if DEBUG
    dr_printf("INFO: post malloc wrap with ptr: %p and size: %d\n", return_address, malloc_size);
#endif
    return_address = tag_ptr_mem(return_address, malloc_size);

    insert_to_tree(return_address, malloc_size);

    malloc_size = 0;

    DR_ASSERT_MSG(
        drwrap_set_retval(wrapcxt, return_address),
        "Cannot tag result pointer of malloc!");

#if DEBUG
    dr_printf("INFO: finished post malloc wrap with ptr: %p\n", return_address);
#endif
}

void calloc_wrap_pre(void *wrapcxt, OUT void **user_data)
{
    size_t nmemb = (size_t)drwrap_get_arg(wrapcxt, 0);
    size_t size = (size_t)drwrap_get_arg(wrapcxt, 1);
    size_t loc_calloc_size = nmemb * size;

    calloc_size = align(loc_calloc_size, MTE_GRANULARITY);

#if DEBUG
    dr_printf("INFO: pre calloc wrap, with calloc_size: %d\n", loc_calloc_size);
#endif
}

void calloc_wrap_post(void *wrapcxt, void *user_data)
{
#if DEBUG
    dr_printf("INFO: post calloc wrap\n");
#endif

    void *return_address = drwrap_get_retval(wrapcxt);
    DR_ASSERT_MSG(
        return_address != NULL,
        "Calloc return NULL pointer");

    return_address = tag_ptr_mem(return_address, calloc_size);
    insert_to_tree(return_address, calloc_size);

    calloc_size = 0;

    DR_ASSERT_MSG(
        drwrap_set_retval(wrapcxt, return_address),
        "Cannot tag result pointer of calloc!");

#if DEBUG
    dr_printf("INFO: finished calloc with ptr: %p\n", return_address);
#endif
}

void realloc_wrap_pre(void *wrapcxt, OUT void **user_data)
{
    void *ptr = drwrap_get_arg(wrapcxt, 0);
    size_t size = (size_t)drwrap_get_arg(wrapcxt, 1);
    realloc_size = align(size, MTE_GRANULARITY);

    size_t new_size = realloc_size;
    drwrap_set_arg(wrapcxt, 1, (void *)new_size);

#if DEBUG
    dr_printf("INFO: finished realloc with new size: %d\n", new_size);
#endif
}

void realloc_wrap_post(void *wrapcxt, void *user_data)
{
    void *return_address = drwrap_get_retval(wrapcxt);
    DR_ASSERT_MSG(
        return_address != NULL,
        "Realloc return NULL pointer");

    return_address = tag_ptr_mem(return_address, realloc_size);
    insert_to_tree(return_address, realloc_size);

    realloc_size = 0;

    DR_ASSERT_MSG(
        drwrap_set_retval(wrapcxt, return_address),
        "Cannot tag result pointer of realloc!");
#if DEBUG
    dr_printf("INFO: post realloc wrap\n");
#endif
}

void free_wrap_pre(void *wrapcxt, OUT void **user_data)
{
    void *ptr_to_free = drwrap_get_arg(wrapcxt, 0);
#if DEBUG
    dr_printf("INFO: pre free wrap with ptr: %p\n", ptr_to_free);
#endif
    unsigned long key = (unsigned long)ptr_to_free;

    // alternative to tree search: malloc_usable_size(ptr_to_free)
    size_t *size_ptr = (size_t *)search(address_to_size, key);

    if (size_ptr == NULL)
    {
        dr_printf("ERROR: double free (CWE 415) or Free Pointer Not at Start of Buffer (CWE 761) happend.\n");
        exit(1);
    }
    else
    {
        size_t size = *size_ptr;
        void *ptr = (void *)CLEAR_TAG(ptr_to_free);

        tag_mem((unsigned long)ptr, size);

#if DEBUG
        dr_printf("INFO: finished retagging with ptr: %p.\n", ptr);
#endif
        rem(address_to_size, key);

        drwrap_set_arg(wrapcxt, 0, ptr);
    }
}

void free_wrap_post(void *wrapcxt, void *user_data)
{
}
