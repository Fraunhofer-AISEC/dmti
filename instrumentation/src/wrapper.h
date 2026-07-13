#ifndef WRAPPER_H
#define WRAPPER_H 1

#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/mman.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"
#include "dr_config.h"

#include "tree.h"
#include "tagger.h"

// #include <scudo/interface.h>

#ifndef MTE_GRANULARITY
#define MTE_GRANULARITY 16
#endif

#ifndef FRAME_SIZE
#define FRAME_SIZE 1024
#endif

void alloca_wrap_pre(void *wrapcxt, OUT void **user_data);
void alloca_wrap_post(void *wrapcxt, void *user_data);

void malloc_wrap_pre(void *wrapcxt, OUT void **user_data);
void malloc_wrap_post(void *wrapcxt, void *user_data);

void calloc_wrap_pre(void *wrapcxt, OUT void **user_data);
void calloc_wrap_post(void *wrapcxt, void *user_data);

void realloc_wrap_pre(void *wrapcxt, OUT void **user_data);
void realloc_wrap_post(void *wrapcxt, void *user_data);

void free_wrap_pre(void *wrapcxt, OUT void **user_data);
void free_wrap_post(void *wrapcxt, void *user_data);

#endif // WRAPPER_H