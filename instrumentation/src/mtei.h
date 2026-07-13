/**
 * @file mtei.h
 * @author Andreas Hager (andreas.hager@aisec.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2022-08-01
 *
 * @copyright Copyright (c) 2022
 */

#ifndef MTEI_H
#define MTEI_H 1

#define _GNU_SOURCE

#include <errno.h>
#include <string.h>
#include <link.h>
#include <regex.h>
#include <sys/mman.h>

#define UNIX    // set OS
#define AARCH64 // set architecture
#define AARCHXX // set architecture

#define TAG_FRAME false
#define INSTRUMENT_FRAME false

#define RESTORE_ADDR_AFTER_INSTRUMENT true

#define UNTAG_EPILOG true

#define ALIGN_STACK true      // is necessary to receive correct addresses
#define INSTRUMENT_STACK true // for instrumenting the stack with mts

#define INSTRUMENT_GLOBALS true // for instrumenting the globals with mts
#define WRAP_FUNCTION true       // or instrumenting the heap with mts

#define COUNT_BBS_AND_INSTRUCTIONS false

#ifndef DEBUG
#define DEBUG false
#endif
#ifndef VERBOUSE
#define VERBOUSE false
#endif
#ifndef WARNING
#define WARNING false
#endif
#ifndef HEX_BASE
#define HEX_BASE 16
#endif
#ifndef MTE_GRANULARITY
#define MTE_GRANULARITY 16
#endif
/*
 * From arch/arm64/include/uapi/asm/mman.h
 */
#ifndef PROT_MTE
#define PROT_MTE 0x20
#endif
#ifndef MTE_ERR_CODE
#define MTE_ERR_CODE 1
#endif
#ifndef SEGV_ERR_CODE
#define SEGV_ERR_CODE 139
#endif


#include "dr_api.h"
#include "drmgr.h"
#include "drwrap.h"

// #include "helper_functions.h"
#include "parser.h"
#include "wrapper.h"
#include "tagger.h"

const int MIN_ARG_COUNT = 2;
const char *MAPS_PATH = "/proc/self/maps";
const int RANGE_LEN = 34;
const int FLAGS_LEN = 5;
const int READABLE_FLAG_INDEX = 0;
const int WRITABLE_FLAG_INDEX = 1;
const int EXECUTABLE_FLAG_INDEX = 2;
const char READABLE_FLAG = 'r';
const char WRITABLE_FLAG = 'w';
const char EXECUTABLE_FLAG = 'x';
const char *WHITESPACE_DELIM = " ";
const char *ADDR_RANGE_DELIM = "-";
const unsigned long GHIDRA_BASE = 0x00100000;
const int ADD_OP = 9;
const int SUB_OP = 470;
const int LDP_OP = 225;
const int STP_OP = 456;
const int RET_OP = 336;

// Mutable Global variables !!!! --->
unsigned long target_address_space = 0;
bool main_passed = false;
ParsedMeta *parsed_meta = NULL;
#if COUNT_BBS_AND_INSTRUCTIONS
unsigned long instruction_added_count = 0;
unsigned long total_instruction_count = 0; // excluding added instructions
unsigned long bb_modified_count = 0; 
unsigned long total_bb_count = 0;
#endif
// <---

typedef struct
{
    size_t old_stack_off;
    size_t new_stack_off;
    size_t new_size;
} OffsetMap;

typedef struct
{
    size_t old_stack_size;
    size_t new_stack_size;
    size_t off_count;
    OffsetMap *off_map;
} StackInfo;

typedef struct
{
    Variable *var;
    size_t var_index;
    bool isUsage;
} Access;

typedef struct
{
    uint64_t start;
    uint64_t end;
    char *flags;
} Range;
uint to_prot_flags(const char flags[FLAGS_LEN]);

static void module_load_event(void *drcontext, const module_data_t *mod, bool loaded);

/**
 * @brief hook on exit event
 */
static void event_exit(void);

/**
 * @brief
 *
 * @param drcontext pointer to the input program's machine context.
 *                  Should not be inspected or modified!
 * @param tag unique identifier for the BB fragment (Memory address of first instruction)
 * @param dr_bb pointer to the list of instructions that comprise the BB
 */
void print_bb(void *drcontext, void *tag, instrlist_t *dr_bb);
char *read_file(const char *file_name);
void set_target_address_space(const char *target_name);
static dr_emit_flags_t tag_memory(
    void *drcontext,
    void *tag,
    instrlist_t *dr_bb,
    bool for_trace,
    bool translating);
void tag_globals();

/**
 * @brief Entrypoint of the Client.
 *
 * Start this client with the folowing command (aarch64):
 * ${DynamoRIO_Base}/bin64 -c ${DynamoRIO_Base}/samples/mtei/bin/libmtei.so <FQP_to_InsertPointFile> -- <Target>
 *
 * @param id  ID supplied at registration
 * @param argc Argument count
 * @param argv Arguments passed to the client
 * @return DR_EXPORT
 */
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]);


#endif // MTEI_H