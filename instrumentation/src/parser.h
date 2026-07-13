#ifndef PARSER_H
#define PARSER_H 1

#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

#include <cjson/cJSON.h>

#include "tree.h"
#include "dr_api.h"

#ifndef HEX_BASE
#define HEX_BASE 16
#endif
#ifndef DEZ_BASE
#define DEZ_BASE 10
#endif
#ifndef DEBUG
#define DEBUG 0
#endif

typedef struct
{
    bool is_stack_variable;
    bool is_memory_variable;
    bool is_Register_variable;
    bool is_instrumented;
    size_t stack_offset;
    size_t size;
    size_t usage_count;
    unsigned long *usages;
#if ALIGN_STACK
    size_t access_count;
    unsigned long *accesses;
#endif
} Variable;

typedef struct
{
    unsigned long start_address;
    unsigned long end_address;
    size_t stack_size;
    size_t prolog_len;
    size_t epilog_len;
    size_t var_count;
    Variable *vars;
} Function;

typedef struct
{
    unsigned long start_address;
    unsigned long end_address;
    Function *function;
} BasicBlock;

typedef struct
{
    unsigned long address;
    size_t size;
    size_t referee_count;
    unsigned long *referee_address;
    bool is_tagged;
} GlobalVariable;

typedef struct
{
    size_t globals_count;
    GlobalVariable *global_variables;
} Globals;

/**
 * @brief structured MetaData
 *
 * The Parsted metadata contains:
 *  - The main address.
 *  - A tree to mapp code addresses (insertion points)
 *      to the relating memory objects defined by the
 *      BasicBlock structure.
 *  - Information about Globals.
 */
typedef struct
{
    unsigned long main_address;
    Tree *addr_to_bb;
    Globals *globals;
} ParsedMeta;

/**
 * @brief Parse the given file into `InstPoints`
 *
 * @param file_name the name of the File to parse.
 *                  It should exist and be readable.
 *                  It should contain json plain text.
 * @return ParsedMeta* the parsed meta data.
 */
ParsedMeta *parse_file(const char *file_name);

#endif // PARSER_H