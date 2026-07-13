/**
 * @file mtei.c
 * @author Andreas Hager (andreas.hager@aisec.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2022-08-01
 *
 * @copyright Copyright (c) 2022
 */

#include "mtei.h"

void handler(int sig, siginfo_t *si, void *vcontext)
{
#if VERBOSE
    dr_printf("INFO: Signal %d occured\n", sig);
#endif

    if (si == NULL)
    {
        dr_printf("ERROR: Signal %d; with no signal info!\n", sig);
        _exit(SEGV_ERR_CODE);
    }
    if (si->si_code == SEGV_MTESERR || si->si_code == SEGV_MTEAERR)
    {
        dr_printf("ERROR: Handle Signal %d; return MTE error %d.\n", sig, MTE_ERR_CODE);
        dr_printf("  Memory location that caused the fault: %p [%p; %p].\n", si->si_addr, si->si_lower, si->si_upper);

        _exit(MTE_ERR_CODE);
    }
    _exit(SEGV_ERR_CODE);
}

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
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    const char *target_name = dr_get_application_name();
    DR_ASSERT_MSG(
        target_name != NULL,
        "Cannot get traget name!");
    dr_printf("INFO: start MTEI with Target: %s\n", target_name);

    // check and parse input file
    DR_ASSERT_MSG(
        argc <= MIN_ARG_COUNT,
        "The fully qualified path to the insert point JSON file should be provided!");
    DR_ASSERT_MSG(
        argc >= MIN_ARG_COUNT,
        "Only two files are allowed!");

    const char *file_name = argv[1];
    DR_ASSERT_MSG(
        strlen(file_name) > 0,
        "The filename should not be empty!");

    parsed_meta = parse_file(file_name);
    DR_ASSERT(parsed_meta != NULL);
    DR_ASSERT(parsed_meta->main_address != 0);

    struct sigaction sa = {0};
    sa.sa_sigaction = &handler;
    sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
    {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    // register Clients
    dr_set_client_name(
        "Memory Tagging Extension Instrumenter Client 'MTEI'",
        // report issues to:
        "https://github.com/Fraunhofer-AISEC/dmti/issues");

    drmgr_init();
    drwrap_init();

    dr_register_exit_event(event_exit);

#if TAG_FRAME || INSTRUMENT_FRAME || UNTAG_EPILOG || ALIGN_STACK || INSTRUMENT_STACK || INSTRUMENT_GLOBALS
    drmgr_register_bb_app2app_event(tag_memory, NULL);
#endif

    drmgr_register_module_load_event(module_load_event);

    /* Make it easy to tell from the log file which client executed. */
    dr_log(NULL, DR_LOG_ALL, 1, "Client 'MTEI' initializing\n");
}

Range *parse_range(char *buffer)
{
    Range *r = malloc(sizeof(Range));
    r->flags = calloc(FLAGS_LEN, sizeof(char));

    char range[RANGE_LEN];
    char *elem = strtok(buffer, WHITESPACE_DELIM);

    strncpy(range, elem, RANGE_LEN - 1);
    range[RANGE_LEN - 1] = 0;

    elem = strtok(NULL, WHITESPACE_DELIM);
    strncpy(r->flags, elem, FLAGS_LEN - 1);
    r->flags[FLAGS_LEN - 1] = 0;

    char *start = strtok(range, ADDR_RANGE_DELIM);
    const char size = 19; // leading ox: 2 + 8 byte string + zero byte
    DR_ASSERT_MSG(
        strlen(start) <= size,
        "Encountering false range lengt");

    char start_address[size];
    start_address[0] = '0';
    start_address[1] = 'x';
    strncpy(start_address + 2, start, size - 3);
    start_address[size - 1] = 0;
    r->start = strtoul(start_address, NULL, HEX_BASE);

    char *end = strtok(NULL, ADDR_RANGE_DELIM);
    char end_address[size];
    end_address[0] = '0';
    end_address[1] = 'x';
    DR_ASSERT_MSG(
        strlen(end) <= size,
        "Encountering false range lengt");
    strncpy(end_address + 2, end, size - 3);
    end_address[size - 1] = 0;

    r->end = strtoul(end_address, NULL, HEX_BASE);
    return r;
}

uint to_prot_flags(const char flags[FLAGS_LEN])
{
    int flag_res = 0;

    char readable_flag = flags[READABLE_FLAG_INDEX];
    if (readable_flag == READABLE_FLAG)
    {
        flag_res |= PROT_READ;
    }
    else
    {
        DR_ASSERT(readable_flag == '-');
    }

    char writable_flag = flags[WRITABLE_FLAG_INDEX];
    if (writable_flag == WRITABLE_FLAG)
    {
        flag_res |= PROT_WRITE;
    }
    else
    {
        DR_ASSERT(writable_flag == '-');
    }

    char executable_flag = flags[EXECUTABLE_FLAG_INDEX];
    if (executable_flag == EXECUTABLE_FLAG)
    {
        flag_res |= PROT_EXEC;
    }
    else
    {
        DR_ASSERT(executable_flag == '-');
    }

    DR_ASSERT(flags[FLAGS_LEN - 2] == 'p');

    return flag_res;
}

void set_target_address_space(const char *target_name)
{
    FILE *filePointer = fopen(MAPS_PATH, "rb");
    DR_ASSERT_MSG(
        filePointer != NULL,
        "Cannot open /proc/self/maps");
    const long bufferLength = 1024;
    char *buffer = calloc(bufferLength, sizeof(char));
    bool is_last_target = false;
    while (fgets(buffer, bufferLength, filePointer))
    {
#if DEBUG
        dr_printf("%s", buffer);
#endif
        bool is_target = strstr(buffer, target_name) != NULL;
        bool is_stack = strstr(buffer, "[stack]") != NULL;

        Range *range = parse_range(buffer);

        bool is_readabe = range->flags[READABLE_FLAG_INDEX] == READABLE_FLAG;
        bool is_writable = range->flags[WRITABLE_FLAG_INDEX] == WRITABLE_FLAG;
        bool is_executable = range->flags[EXECUTABLE_FLAG_INDEX] == EXECUTABLE_FLAG;
#if DEBUG
        dr_printf("%s", buffer);
#endif
        if ((is_target || is_stack || is_last_target) && is_readabe && is_writable && !is_executable)
        {
#if VERBOUSE
            dr_printf("Re-Protecting %lX-%lX %s", range->start, range->end, range->flags);
            if (is_target)
            {
                dr_printf(" [rw_globals in: %s]\n", target_name);
            }
            if (is_stack)
            {
                dr_printf(" [stack]\n");
            }
            if (is_last_target)
            {
                dr_printf(" [heap]\n");
            }
#endif
            if (mprotect(
                    (void *)range->start,
                    range->end - range->start,
                    to_prot_flags(range->flags) | PROT_MTE) != 0)
            {
                dr_printf("ERROR: mprotect() failed: Cannot reprotect ");
                if (is_target)
                {
                    dr_printf("rw_globals in: %s", target_name);
                }
                if (is_stack)
                {
                    dr_printf("stack");
                }
                if (is_last_target)
                {
                    dr_printf("heap");
                }
                dr_printf(" [0x%x - 0x%x]!\n", range->start, range->end);
            }

            if (is_last_target)
            {
                is_last_target = false;
            }
            if (is_target)
            {
                is_last_target = true;
            }
        }

        if (is_target && is_executable)
        {
            target_address_space = range->start;
#if DEBUG
            dr_printf("%ld (%lX)\n", target_address_space, target_address_space);
#endif
        }
        free(range->flags);
        free(range);
    }
    free(buffer);
    fclose(filePointer);
    DR_ASSERT_MSG(
        target_address_space != 0,
        "Cannot detect the address space of the target module!");
}

void wrapp_func(
    app_pc to_wrap,
    void (*pre_func)(void *wrapcxt, void **user_data),
    void (*post_func)(void *wrapcxt, void *user_data))
{
    if (to_wrap != NULL)
    {
        if (!drwrap_is_wrapped(to_wrap, pre_func, post_func))
        {
            bool ok = drwrap_wrap(to_wrap, pre_func, post_func);
            if (ok)
            {
#if VERBOUSE
                dr_printf("  INFO: Wrapped function %s (%lX) with pre: %lX, post: %lX\n", func_to_wrap, to_wrap, pre_func, post_func);
#endif
            }
            else
            {
                dr_printf("  ERROR: Couldn't replace func at: %lX\n", to_wrap);
            }
        }
#if VERBOUSE
        else
        {
            dr_printf("  INFO: function %lX is aleready replaced\n", to_wrap);
        }
#endif
    }
#if VERBOUSE
    else
    {
        dr_printf("  INFO: function %lX not found\n", to_wrap);
    }
#endif
}

void wrapp_func_by_name(
    const char *func_to_wrap,
    const module_data_t *mod,
    void (*pre_func)(void *wrapcxt, void **user_data),
    void (*post_func)(void *wrapcxt, void *user_data))
{
    app_pc to_wrap = (app_pc)dr_get_proc_address(mod->handle, func_to_wrap);
    wrapp_func(to_wrap, pre_func, post_func);
}

static void module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{

    const char *mod_name = dr_module_preferred_name(mod);
#if DEBUG
    dr_printf("mod: %s\n", mod_name);
#endif
#if WRAP_FUNCTION
    wrapp_func_by_name("alloca", mod, alloca_wrap_pre, alloca_wrap_post);
    wrapp_func_by_name("malloc", mod, malloc_wrap_pre, malloc_wrap_post);
    wrapp_func_by_name("realloc", mod, realloc_wrap_pre, realloc_wrap_post);
    wrapp_func_by_name("calloc", mod, calloc_wrap_pre, calloc_wrap_post);
    wrapp_func_by_name("free", mod, free_wrap_pre, free_wrap_post);
#endif

    module_data_t *main_mod = dr_get_main_module();
    const char *main_mod_name = dr_module_preferred_name(main_mod);

    if (strcmp(mod_name, main_mod_name) == 0)
    {
#if VERBOUSE
        dr_printf("Main module load! preferred name: %s\n", main_mod_name);
#endif
        /*
         * Enable the tagged address ABI, synchronous or asynchronous MTE
         * tag check faults (based on per-CPU preference) and allow all
         * non-zero tags in the randomly generated set.
         */
        if (prctl(PR_SET_TAGGED_ADDR_CTRL,
                  PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC |
                      (0xfffe << PR_MTE_TAG_SHIFT),
                  0, 0, 0))
        {
            perror("ERROR: prctl() failed");
            // This call returns -1 on the Galaxy S22
            // exit(EXIT_FAILURE);
        }
        // set main  module start address
        set_target_address_space(main_mod_name);
        // tag_globals();
    }
    dr_free_module_data(main_mod);
}

int get_next_multipe(const int number, const int base)
{
    int num = abs(number);
    int result = num;

    if (num % base != 0)
    {
        result = ((number < 0 ? number - 1 : number + 1) / base + 1) * base;
    };

    int sign = number < 0 ? -1 : 1;
    return sign * result;
}

unsigned long map_addr(const unsigned long addr)
{
    DR_ASSERT_MSG(
        target_address_space != 0,
        "Cannot detect the address space of the target module!");
    return GHIDRA_BASE | (addr - target_address_space);
}

unsigned long re_map_addr(const unsigned long addr)
{
    DR_ASSERT_MSG(
        target_address_space != 0,
        "Cannot detect the address space of the target module!");
    return ((~GHIDRA_BASE & addr) + target_address_space);
}

void tag_globals()
{
    DR_ASSERT(parsed_meta != NULL);
    Globals *globals = parsed_meta->globals;
    DR_ASSERT(globals != NULL);
    for (int i = 0; i < globals->globals_count; i++)
    {
        GlobalVariable gvar = globals->global_variables[i];
        if (gvar.address % 16 == 0)
        {
            dr_printf("gvar before: 0x%lX, ", gvar.address);
            unsigned long target_address = (re_map_addr(gvar.address) / MTE_GRANULARITY) * MTE_GRANULARITY;
            dr_printf("target_address: 0x%lX\n", target_address);
            globals->global_variables[i].address = (unsigned long)tag_ptr_mem((void *)target_address, gvar.size);
            dr_printf("after: 0x%lX\n", globals->global_variables[i].address);
        }
    }
}

StackInfo *calculate_stack_info(BasicBlock *ghidra_bb)
{
    Function *function = ghidra_bb->function;
    DR_ASSERT(function != NULL);
    Variable *vars = function->vars;
    DR_ASSERT(vars != NULL);
    const size_t var_count = function->var_count;

    size_t old_stack_size = 0;
    size_t stack_size = 0;
    if (var_count > 0)
    {
        Variable first = vars[0];
        stack_size = abs(get_next_multipe(first.stack_offset, MTE_GRANULARITY));
        Variable last = vars[var_count - 1];
        old_stack_size = function->stack_size;
    }
    OffsetMap *off_map = malloc(var_count * sizeof(OffsetMap));
    DR_ASSERT(off_map != NULL);

    for (int i = 0; i < var_count; i++)
    {
        Variable var = vars[i];

        OffsetMap offset = off_map[i];
        offset.old_stack_off = var.stack_offset > 0x100 ? 0 : var.stack_offset;
        offset.new_size = get_next_multipe(var.size > 0x100 ? 0 : var.size, MTE_GRANULARITY);
        offset.new_stack_off = stack_size - abs(offset.old_stack_off);
        off_map[i] = offset;

        stack_size += offset.new_size;

#if VERBOUSE
        dr_printf(
            "Var %2ld: Offset: 0x%2lx + 0x%2lx -> 0x%2lx : size: 0x%2lx -> 0x%2lx; stack_size: %lx -> %lx\n",
            i,
            abs(offset.old_stack_off),
            abs(offset.new_stack_off),
            abs(offset.old_stack_off) + abs(offset.new_stack_off),
            abs(var.size),
            abs(offset.new_size),
            abs(old_stack_size),
            abs(stack_size));
#endif
    }
    if (old_stack_size > abs(stack_size))
    {
        stack_size = old_stack_size;
    }
    StackInfo *stack_info = malloc(sizeof(StackInfo));
    DR_ASSERT(stack_info != NULL);
    stack_info->old_stack_size = old_stack_size;
    stack_info->new_stack_size = abs(stack_size);
    stack_info->off_count = var_count;
    stack_info->off_map = off_map;
    return stack_info;
}

Access *get_access(Function *function, instr_t *instr)
{
    DR_ASSERT(function != NULL);
    Variable *vars = function->vars;
    DR_ASSERT(vars != NULL);

    const long pc = (long)instr_get_app_pc(instr);
    const unsigned long instr_addr = map_addr((unsigned long)pc);

    Access *access = malloc(sizeof(Access));
    access->var = NULL;
    access->var_index = -1;
    access->isUsage = false;
    DR_ASSERT(access != NULL);
    for (int i = 0; i < function->var_count; i++)
    {
        Variable var = vars[i];

        for (int j = 0; j < var.usage_count && access->var == NULL; j++)
        {
            const unsigned long usage = (unsigned long)var.usages[j];
            if (instr_addr == usage)
            {
                access->var = &vars[i];
                access->var_index = i;
                access->isUsage = true;
            }
        }
#if ALIGN_STACK
        for (int j = 0; j < var.access_count && access->var == NULL; j++)
        {
            const unsigned long acc = (unsigned long)var.accesses[j];
            if (instr_addr == acc)
            {
                access->var = &vars[i];
                access->var_index = i;
            }
        }
#endif
    }
    return access;
}

void wrap_main(void *drcontext, instrlist_t *dr_bb)
{
    instr_t *first = instrlist_first(dr_bb);
    app_pc main_addr = instr_get_app_pc(first);
    const unsigned long first_addr = map_addr((unsigned long)main_addr);
    DR_ASSERT_MSG(parsed_meta->main_address != 0, "ERROR: no main address was provided");
    if (first_addr == parsed_meta->main_address)
    {
#if VERBOUSE
        dr_printf("INFO: MAIN found: 0x%lX (0x%lX)\n", first_addr, main_addr);
#endif
        main_passed = true;
    }
#if DEBUG
    else
    {
        dr_printf("INFO: not main: %lX (%lX)\n", first_addr, parsed_meta->main_address);
    }
#endif
}

bool is_reg(opnd_t opnd)
{
    return !opnd_is_null(opnd) && opnd_is_reg(opnd);
}

int get_src_reg(instr_t *instr)
{
    const int src_count = instr_num_srcs(instr);

    opnd_t reg;
    bool src_reg_found = false;

    for (int src_pos = 0; src_pos < src_count && !src_reg_found; src_pos++)
    {
        opnd_t src = instr_get_src(instr, src_pos);
        if (is_reg(src))
        {
            reg = src;
            src_reg_found = true;
        }
        else if (opnd_is_base_disp(src))
        {
            reg = opnd_create_reg(opnd_get_base(src));
            src_reg_found = true;
        }
    }
    if (!src_reg_found)
    {
        return -1;
    }
    uint reg_size = opnd_size_in_bits(opnd_get_size(reg));
    reg_id_t reg_id = opnd_get_reg(reg);
    if (reg_size == (uint)32)
    {
        reg_id = reg_32_to_64(reg_id);
    }
    return (int)reg_id;
}

opnd_t get_dst_reg(instr_t *instr)
{
    const int dst_count = instr_num_dsts(instr);

    opnd_t reg;
    bool dst_reg_found = false;
    for (int dst_pos = 0; dst_pos < dst_count; dst_pos++)
    {
        opnd_t dst = instr_get_dst(instr, dst_pos);
        if (is_reg(dst))
        {
            reg = dst;
            dst_reg_found = true;
        }
    }

    DR_ASSERT_MSG(dst_reg_found, "Cannot find dst reg!");
    uint reg_size = opnd_size_in_bits(opnd_get_size(reg));
    reg_id_t reg_id = opnd_get_reg(reg);
    if (reg_size == (uint)32)
    {
        reg_id = reg_32_to_64(reg_id);
    }

    return opnd_create_reg(reg_id); // must be a 64 bit register
}

bool contains_reg(instr_t *instr, reg_id_t r)
{
    const int src_count = instr_num_srcs(instr);
    bool found = false;

    for (int src_pos; src_pos < src_count; src_pos++)
    {
        opnd_t src = instr_get_src(instr, src_pos);
        if (
            is_reg(src) && opnd_get_reg(src) == r || opnd_is_base_disp(src) && opnd_get_base(src) == r)
        {
            found = true;
        }
    }
    return found;
}

void align_var_access(
    void *drcontext,
    instrlist_t *dr_bb,
    BasicBlock *ghidra_bb,
    StackInfo *stack_info)
{
    DR_ASSERT(ghidra_bb != NULL);
    Function *function = ghidra_bb->function;
    DR_ASSERT(function != NULL);
    Variable *vars = function->vars;
    DR_ASSERT(vars != NULL);
    instr_t *instr, *next;
#if COUNT_BBS_AND_INSTRUCTIONS
    bool modified = false;
#endif
    for (instr = instrlist_first(dr_bb); instr != NULL; instr = next)
    {
        next = instr_get_next(instr);

        Access *access = get_access(function, instr);
        OffsetMap *off_map = stack_info->off_map;
        OffsetMap stack_change = off_map[access->var_index];
        if (access->var != NULL && access->var_index > -1 && stack_change.new_stack_off != 0 /*&& !(op == LDP_OP || op == STP_OP)*/)
        {
            const int stack_shift = abs(stack_change.new_stack_off);
#if DEBUG
            dr_printf(
                "BB: var %x is accessed at 0x%lx with a shift of: %d\n",
                abs(access->var->stack_offset),
                map_addr((unsigned long)instr_get_app_pc(instr)),
                stack_shift);
#endif
#if COUNT_BBS_AND_INSTRUCTIONS
            modified = true;
#endif
            if (stack_shift > 0 && stack_shift < 0xF0000000)
            {
                size_t max_val = 0xFFF;
                size_t add_val = abs(stack_shift);
                while (add_val > max_val)
                {
                    instrlist_preinsert(
                        dr_bb,
                        instr,
                        INSTR_CREATE_add(
                            drcontext,
                            opnd_create_reg(DR_REG_SP),
                            opnd_create_reg(DR_REG_SP),
                            OPND_CREATE_INT(max_val)));
                    add_val -= max_val;
                }
                instrlist_preinsert(
                    dr_bb,
                    instr,
                    INSTR_CREATE_add(
                        drcontext,
                        opnd_create_reg(DR_REG_SP),
                        opnd_create_reg(DR_REG_SP),
                        OPND_CREATE_INT(add_val)));
#if COUNT_BBS_AND_INSTRUCTIONS
                instruction_added_count++;
#endif

                size_t dec_val = abs(stack_shift);
                while (dec_val > max_val)
                {
                    instrlist_postinsert(
                        dr_bb,
                        instr,
                        INSTR_CREATE_sub(
                            drcontext,
                            opnd_create_reg(DR_REG_SP),
                            opnd_create_reg(DR_REG_SP),
                            OPND_CREATE_INT(max_val)));
                    dec_val -= max_val;
                }
                instrlist_postinsert(
                    dr_bb,
                    instr,
                    INSTR_CREATE_sub(
                        drcontext,
                        opnd_create_reg(DR_REG_SP),
                        opnd_create_reg(DR_REG_SP),
                        OPND_CREATE_INT(dec_val)));
#if COUNT_BBS_AND_INSTRUCTIONS
                instruction_added_count++;
#endif
            }
        }
        free(access);
    }
#if COUNT_BBS_AND_INSTRUCTIONS
    if (modified)
    {
        bb_modified_count++;
    }
#endif
}

void align_prolog(
    void *drcontext,
    instrlist_t *dr_bb,
    BasicBlock *ghidra_bb,
    StackInfo *stack_info)
{
    // stp    %lX29 %lX30 %sp $0xf..fe0 -> -0x20(%sp)[16byte] %sp
    Function *function = ghidra_bb->function;
    DR_ASSERT(function != NULL);
    instr_t *first = instrlist_first(dr_bb);
    const unsigned long first_addr = map_addr((unsigned long)instr_get_app_pc(first));
    if (ghidra_bb->start_address == function->start_address && first_addr == function->start_address)
    {
#if VERBOUSE
        dr_printf("INFO: Function start detected at address: 0x%lX with stack size: %d bytes\n", first_addr, stack_info->new_stack_size);
#endif
        if (instr_get_opcode(first) == SUB_OP)
        {
            first = instr_get_next(first);
        }
        if (stack_info->new_stack_size < 256 && false)
        {
            instr_set_src(first, 3, OPND_CREATE_INT(-stack_info->new_stack_size));
            opnd_t first_dst = instr_get_dst(first, 0);
            opnd_set_disp(&first_dst, -stack_info->new_stack_size);
            instr_set_dst(first, 0, first_dst);
#if COUNT_BBS_AND_INSTRUCTIONS
            bb_modified_count++;
#endif
        }
        else
        {
            DR_ASSERT_MSG(
                stack_info->new_stack_size >= stack_info->old_stack_size,
                "misscalculated new stack size");
            size_t size = abs(stack_info->new_stack_size) - abs(stack_info->old_stack_size);
            DR_ASSERT(size >= 0);
            if (size > 0 && size < 0xF0000000)
            {
                size_t max_val = 0xFFF;
                size_t dec_val = abs(size);
                while (dec_val > max_val)
                {
                    instrlist_postinsert(
                        dr_bb,
                        first,
                        INSTR_CREATE_sub(
                            drcontext,
                            opnd_create_reg(DR_REG_SP),
                            opnd_create_reg(DR_REG_SP),
                            OPND_CREATE_INT(max_val)));
                    dec_val -= max_val;
                }
                instrlist_postinsert(
                    dr_bb,
                    first,
                    INSTR_CREATE_sub(
                        drcontext,
                        opnd_create_reg(DR_REG_SP),
                        opnd_create_reg(DR_REG_SP),
                        OPND_CREATE_INT(dec_val)));
            }

#if COUNT_BBS_AND_INSTRUCTIONS
            instruction_added_count++;
#endif
#if COUNT_BBS_AND_INSTRUCTIONS
            bb_modified_count++;
#endif
        }
    }
}

void align_epilog(
    void *drcontext,
    instrlist_t *dr_bb,
    BasicBlock *ghidra_bb,
    StackInfo *stack_info)
{
    Function *function = ghidra_bb->function;
    DR_ASSERT(function != NULL);
    Variable *vars = function->vars;
    DR_ASSERT(vars != NULL);
    instr_t *instr = instrlist_last(dr_bb);
    const int op = instr_get_opcode(instr);
    if (op == RET_OP)
    {
        for (
            int i = 1;
            instr != NULL && i < function->epilog_len;
            i++)
        { // Does Nothing but setting instr to the first epilog instruction
            instr = instr_get_prev(instr);
        }
        DR_ASSERT_MSG(
            instr != NULL,
            "Got a greather eplilog size, than the last basic block of the function");

        if (stack_info->new_stack_size < 256 && false) // error prone
        {
            instr_set_src(instr, 2, OPND_CREATE_INT(stack_info->new_stack_size));
        }
        else
        {
            size_t max_val = 0xFFF;
            size_t add_val = stack_info->new_stack_size - stack_info->old_stack_size;

            if (add_val < 0xF0000000)
            {
                while (add_val > max_val)
                {
                    instrlist_preinsert(
                        dr_bb,
                        instr,
                        INSTR_CREATE_add(
                            drcontext,
                            opnd_create_reg(DR_REG_SP),
                            opnd_create_reg(DR_REG_SP),
                            OPND_CREATE_INT(max_val)));
                    add_val -= max_val;
                }
                instrlist_preinsert(
                    dr_bb,
                    instr,
                    INSTR_CREATE_add(
                        drcontext,
                        opnd_create_reg(DR_REG_SP),
                        opnd_create_reg(DR_REG_SP),
                        OPND_CREATE_INT(add_val)));
            }
#if COUNT_BBS_AND_INSTRUCTIONS
            instruction_added_count++;
#endif
#if COUNT_BBS_AND_INSTRUCTIONS
            bb_modified_count++;
#endif
        }
    }
}

void untag_in_epilog(
    void *drcontext,
    instrlist_t *dr_bb,
    BasicBlock *ghidra_bb)
{
    Function *function = ghidra_bb->function;
    DR_ASSERT(function != NULL);
    instr_t *last = instrlist_last(dr_bb);
    const int op = instr_get_opcode(last);
    if (op == RET_OP && function->stack_size > MTE_GRANULARITY)
    {
        instr_t *instr = instrlist_first(dr_bb);

        size_t granule_count = abs(function->stack_size - 1) / MTE_GRANULARITY;
#if WARNING
        if (granule_count > 200)
        {
            dr_printf("WARNING: huge stack frame with %d granules and size: 0x%lx\n", granule_count, function->stack_size);
        }
#endif
        DR_ASSERT(granule_count > 0);
        int i = 0;
        if (granule_count % 2 == 1)
        {
            instrlist_preinsert(
                dr_bb,
                instr,
                INSTR_CREATE_stg(
                    drcontext,
                    opnd_create_reg(DR_REG_SP),
                    opnd_create_reg(DR_REG_SP),
                    OPND_CREATE_INT(1)));
#if COUNT_BBS_AND_INSTRUCTIONS
            instruction_added_count++;
#endif
            i++;
        }
        for (i; i < granule_count; i += 2)
        {
            instrlist_preinsert(
                dr_bb,
                instr,
                INSTR_CREATE_st2g(
                    drcontext,
                    opnd_create_reg(DR_REG_SP),
                    opnd_create_reg(DR_REG_SP),
                    OPND_CREATE_INT(2)));
#if COUNT_BBS_AND_INSTRUCTIONS
            instruction_added_count++;
#endif
        }
#if RESTORE_ADDR_AFTER_INSTRUMENT
        size_t max_val = 0xFFF;
        size_t dealign = granule_count * MTE_GRANULARITY; /*+ off*/
        while (dealign > max_val)
        {
            instrlist_preinsert(
                dr_bb,
                instr,
                INSTR_CREATE_sub(
                    drcontext,
                    opnd_create_reg(DR_REG_SP),
                    opnd_create_reg(DR_REG_SP),
                    OPND_CREATE_INT16(max_val)));
            dealign -= max_val;
        }
        instrlist_preinsert(
            dr_bb,
            instr,
            INSTR_CREATE_sub(
                drcontext,
                opnd_create_reg(DR_REG_SP),
                opnd_create_reg(DR_REG_SP),
                OPND_CREATE_INT16(dealign)));
#endif
#if COUNT_BBS_AND_INSTRUCTIONS
        instruction_added_count++;
#endif
#if COUNT_BBS_AND_INSTRUCTIONS
        bb_modified_count++;
#endif
    }
}

static void align_stack(
    void *drcontext,
    void *tag,
    instrlist_t *dr_bb,
    BasicBlock *ghidra_bb)
{
    DR_ASSERT(ghidra_bb != NULL);
    app_pc bb_pc = instr_get_app_pc(instrlist_first(dr_bb));
    const unsigned long key = map_addr((unsigned long)bb_pc);

    // add node to tree if not match (retracking)
    instr_t *last = instrlist_last(dr_bb);
    const unsigned long last_addr = map_addr((unsigned long)instr_get_app_pc(last)) + 3; // last byte address

#if VERBOUSE
    dr_printf("// --------------------------------\n");
    dr_printf("INFO: found key: 0x%lX - 0x%lX [0x%lX - 0x%lX]\n", key, last_addr, ghidra_bb->start_address, ghidra_bb->end_address);
#endif

    if (last_addr < ghidra_bb->end_address)
    {
#if VERBOUSE
        dr_printf("## INFO: insert key: %lX, for dr_bb: %lX - %lX\n", last_addr + 1, ghidra_bb->start_address, ghidra_bb->end_address);
#endif
        insert(parsed_meta->addr_to_bb, last_addr + 1, (void *)ghidra_bb);
    }

    // Calculate stack offsets
    StackInfo *stack_info = calculate_stack_info(ghidra_bb);

    if (stack_info->new_stack_size != stack_info->old_stack_size)
    {
        align_prolog(drcontext, dr_bb, ghidra_bb, stack_info);
    }

    align_var_access(drcontext, dr_bb, ghidra_bb, stack_info);

    if (stack_info->new_stack_size != stack_info->old_stack_size)
    {
        align_epilog(drcontext, dr_bb, ghidra_bb, stack_info);
    }

    free(stack_info->off_map);
    stack_info->off_map = NULL;
    free(stack_info);
    stack_info = NULL;
}

static dr_emit_flags_t instrument_vars(
    void *drcontext,
    void *tag,
    instrlist_t *dr_bb,
    BasicBlock *ghidra_bb)
{
    instr_t *first = instrlist_first(dr_bb);

    app_pc bb_pc = instr_get_app_pc(first);
    while (first != NULL && bb_pc == 0)
    {
        first = instr_get_next(first);
        bb_pc = instr_get_app_pc(first);
    }
    DR_ASSERT_MSG(
        bb_pc != 0,
        "Empty basic block");
    const unsigned long key = map_addr((unsigned long)bb_pc);

#if VERBOUSE
    dr_printf("// ---- TAGGING BB 0x%lx (ghidra), 0x%lx (DR)\n", key, bb_pc);
#endif

    Function *function = ghidra_bb->function;
    DR_ASSERT(function != NULL);

    instr_t *instr, *next;
    for (instr = first; instr != NULL; instr = next)
    {
        next = instr_get_next(instr);
        Access *access = get_access(function, instr);
        DR_ASSERT(access != NULL);
        Variable *var = access->var;
        if (var != NULL && var->size > 0 && ((var->stack_offset % MTE_GRANULARITY == 0 && var->size % MTE_GRANULARITY == 0) || TAG_FRAME || ALIGN_STACK))
        {
            const int op = instr_get_opcode(instr);
            if (access->var_index != -1 && access->isUsage)
            {
                var->is_instrumented = var->is_instrumented || TAG_FRAME;

#if DEBUG
                unsigned long inst_addr = map_addr((unsigned long)instr_get_app_pc(instr));
                int index = (inst_addr - key) / 4;
                dr_printf(
                    "BB: %lx var (instrumented: %d): %x is accessed at 0x%lx (%d [+%d]) in op %d\n",
                    key,
                    var->is_instrumented,
                    abs(var->stack_offset),
                    inst_addr,
                    index,
                    index * 4,
                    op);
                print_bb(drcontext, tag, dr_bb);
#endif

                 const int off = abs(var->stack_offset);
                if (op == ADD_OP || op == SUB_OP || TAG_FRAME)
                {
                    opnd_t reg = get_dst_reg(instr);

                    int inst_added = 0;
                    if (var->is_instrumented)
                    {
                        instrlist_postinsert(
                            dr_bb,
                            instr,
                            INSTR_CREATE_ldg(
                                drcontext,
                                reg,
                                reg,
                                OPND_CREATE_INT(0)));
#if COUNT_BBS_AND_INSTRUCTIONS
                        instruction_added_count++;
#endif
                    }
                    else
                    {
                        size_t granule_count = (abs(var->size) - 1) / MTE_GRANULARITY + 1;
                        DR_ASSERT(granule_count > (size_t)0);
#if WARNING
                        if (granule_count > 200)
                        {
                            dr_printf("WARNING: huge stack objekt with %ld granules and size: 0x%lx\n", granule_count, var->size);
                        }
#endif
#if RESTORE_ADDR_AFTER_INSTRUMENT
                        size_t max_val = 0xFFF;
                        size_t dec_val = granule_count * MTE_GRANULARITY /*+ off*/;
                        while (dec_val > max_val)
                        {
                            instrlist_postinsert(
                                dr_bb,
                                instr,
                                INSTR_CREATE_sub(
                                    drcontext,
                                    reg,
                                    reg,
                                    OPND_CREATE_INT(max_val)));
                            dec_val -= max_val;
                        }
                        instrlist_postinsert(
                            dr_bb,
                            instr,
                            INSTR_CREATE_sub(
                                drcontext,
                                reg,
                                reg,
                                OPND_CREATE_INT(dec_val)));
#endif
#if COUNT_BBS_AND_INSTRUCTIONS
                        instruction_added_count++;
#endif

                        int i = 0;
                        if (granule_count % 2 == 1)
                        {
                            instrlist_postinsert(
                                dr_bb,
                                instr,
                                INSTR_CREATE_stg(
                                    drcontext,
                                    reg,
                                    reg,
                                    OPND_CREATE_INT(1)));
#if COUNT_BBS_AND_INSTRUCTIONS
                            instruction_added_count++;
#endif
                            i++;
                        }
                        for (i; i < granule_count; i += 2)
                        {
                            instrlist_postinsert(
                                dr_bb,
                                instr,
                                INSTR_CREATE_st2g(
                                    drcontext,
                                    reg,
                                    reg,
                                    OPND_CREATE_INT(2)));
#if COUNT_BBS_AND_INSTRUCTIONS
                            instruction_added_count++;
#endif
                        }
                        instrlist_postinsert(
                            dr_bb,
                            instr,
                            INSTR_CREATE_irg(
                                drcontext,
                                reg,
                                reg,
                                opnd_create_reg(DR_REG_XZR)));
#if COUNT_BBS_AND_INSTRUCTIONS
                        instruction_added_count++;
#endif

                        var->is_instrumented = true;
                    }
#if COUNT_BBS_AND_INSTRUCTIONS
                    bb_modified_count++;
#endif
                }
                else
                {
#if DEBUG
                    dr_printf("INFO: Cannot instument sp relative indexing\n");
#endif
                }
#if DEBUG
                dr_printf("INFO: Finished var instrumentation\n");
                print_bb(drcontext, tag, dr_bb);
#endif
            }
        }
        free(access);
    }
};

static dr_emit_flags_t instrument_frame(
    void *drcontext,
    void *tag,
    instrlist_t *dr_bb,
    BasicBlock *ghidra_bb)
{
    instr_t *first = instrlist_first(dr_bb);

    app_pc bb_pc = instr_get_app_pc(first);
    while (first != NULL && bb_pc == 0)
    {
        first = instr_get_next(first);
        bb_pc = instr_get_app_pc(first);
    }
    DR_ASSERT_MSG(
        bb_pc != 0,
        "Empty basic block");

    const unsigned long key = map_addr((unsigned long)bb_pc);

    Function *function = ghidra_bb->function;
    DR_ASSERT(function != NULL);

    instr_t *instr, *next;
#if COUNT_BBS_AND_INSTRUCTIONS
    bool modified = false;
#endif
    for (instr = first; instr != NULL; instr = next)
    {
        next = instr_get_next(instr);
        if (contains_reg(instr, (reg_id_t)DR_REG_XSP) || contains_reg(instr, (reg_id_t)DR_REG_X29))
        {
            int reg = get_src_reg(instr);
            const int op = instr_get_opcode(instr);
            if (reg >= 0 && (op == ADD_OP || op == SUB_OP))
            {
                instrlist_preinsert(
                    dr_bb,
                    instr,
                    INSTR_CREATE_ldg(
                        drcontext,
                        opnd_create_reg((reg_id_t)reg),
                        opnd_create_reg((reg_id_t)reg),
                        OPND_CREATE_INT(0)));
#if COUNT_BBS_AND_INSTRUCTIONS
                instruction_added_count++;
#endif
#if COUNT_BBS_AND_INSTRUCTIONS
                modified = true;
#endif
            }
        }
    }
#if COUNT_BBS_AND_INSTRUCTIONS
    if (modified)
    {
        bb_modified_count++;
    }
#endif
#if VERBOUSE
    dr_printf("After Stack Instrumentation:\n");
    print_bb(drcontext, tag, dr_bb);
#endif
};

void tag_frame(
    void *drcontext,
    void *tag,
    instrlist_t *dr_bb,
    BasicBlock *ghidra_bb)
{
    Function *function = ghidra_bb->function;
    DR_ASSERT(function != NULL);

    instr_t *first = instrlist_first(dr_bb);
    const unsigned long first_addr = map_addr((unsigned long)instr_get_app_pc(first));
    if (ghidra_bb->start_address == function->start_address && first_addr == function->start_address)
    {
#if VERBOUSE
        dr_printf("INFO: Function start detected at address: 0x%lX with stack size: %d bytes\n", first_addr, ghidra_bb->function->stack_size);
#endif
        for (int i = 0; i < function->prolog_len; i++)
        {
            first = instr_get_next(first);
        }
        unsigned int granule_count = (ghidra_bb->function->stack_size - 1) / MTE_GRANULARITY + 1;

        instrlist_preinsert(
            dr_bb,
            first,
            INSTR_CREATE_irg(
                drcontext,
                opnd_create_reg(DR_REG_X0),
                opnd_create_reg(DR_REG_XSP),
                opnd_create_reg(DR_REG_XZR)));
#if COUNT_BBS_AND_INSTRUCTIONS
        instruction_added_count++;
#endif
        int i = 0;
        if (granule_count % 2 == 1)
        {
            instrlist_preinsert(
                dr_bb,
                first,
                INSTR_CREATE_stg(
                    drcontext,
                    opnd_create_reg(DR_REG_X0),
                    opnd_create_reg(DR_REG_X0),
                    OPND_CREATE_INT(1)));
#if COUNT_BBS_AND_INSTRUCTIONS
            instruction_added_count++;
#endif
            i++;
        }
        for (i; i < granule_count; i += 2)
        {
            instrlist_preinsert(
                dr_bb,
                first,
                INSTR_CREATE_st2g(
                    drcontext,
                    opnd_create_reg(DR_REG_X0),
                    opnd_create_reg(DR_REG_X0),
                    OPND_CREATE_INT(2)));
#if COUNT_BBS_AND_INSTRUCTIONS
            instruction_added_count++;
#endif
        }

        instrlist_preinsert(
            dr_bb,
            first,
            INSTR_CREATE_sub(
                drcontext,
                opnd_create_reg(DR_REG_X0),
                opnd_create_reg(DR_REG_X0),
                OPND_CREATE_INT(granule_count * MTE_GRANULARITY)));
#if COUNT_BBS_AND_INSTRUCTIONS
        instruction_added_count++;
#endif
#if COUNT_BBS_AND_INSTRUCTIONS
        bb_modified_count++;
#endif
#if VERBOUSE
        dr_printf("After Stack Tagging:\n");
        print_bb(drcontext, tag, dr_bb);
#endif
    }
#if VERBOUSE
    dr_printf("BB:\n");
    print_bb(drcontext, tag, dr_bb);
#endif
}

GlobalVariable *get_accessing_global(instr_t *instr)
{
    DR_ASSERT_MSG(
        parsed_meta != NULL,
        "The Metadata was not correctly parsed");
    Globals *glob = parsed_meta->globals;

    const long pc = (long)instr_get_app_pc(instr);
    const unsigned long instr_addr = map_addr((unsigned long)pc);
    for (int i = 0; i < glob->globals_count; i++)
    {
        GlobalVariable gvar = glob->global_variables[i];
        for (int j = 0; j < gvar.referee_count; j++)
        {
            const unsigned long referee_address = gvar.referee_address[j];
            if (instr_addr == referee_address)
            {
                return &glob->global_variables[i];
            }
            else
            {
#if DEBUG
                dr_printf("instr_addr (%lX) != referee_address (%lX)\n", instr_addr, referee_address);
#endif
            }
        }
    }
    return NULL;
}

static dr_emit_flags_t instrument_globals(
    void *drcontext,
    void *tag,
    instrlist_t *dr_bb)
{
#if COUNT_BBS_AND_INSTRUCTIONS
    bool modified = false;
#endif
    instr_t *instr, *next;
    int i = 0;
    for (instr = instrlist_first(dr_bb); instr != NULL; instr = next)
    {
        next = instr_get_next(instr);
        GlobalVariable *gvar = get_accessing_global(instr);
        if (gvar != NULL && gvar->address % 16 == 0)
        {
             opnd_t reg = get_dst_reg(instr);
            int inst_added = 0;
#if COUNT_BBS_AND_INSTRUCTIONS
            modified = true;
#endif
            if (gvar->is_tagged)
            {
                instrlist_postinsert(
                    dr_bb,
                    instr,
                    INSTR_CREATE_ldg(
                        drcontext,
                        reg,
                        reg,
                        OPND_CREATE_INT(0)));
                inst_added++;
#if COUNT_BBS_AND_INSTRUCTIONS
                instruction_added_count++;
#endif
            }
            else
            {
                unsigned int granule_count = (gvar->size - 1) / MTE_GRANULARITY + 1;
#if RESTORE_ADDR_AFTER_INSTRUMENT
                instrlist_postinsert(
                    dr_bb,
                    instr,
                    INSTR_CREATE_sub(
                        drcontext,
                        reg,
                        reg,
                        OPND_CREATE_INT((granule_count)*MTE_GRANULARITY)));
                inst_added++;
#endif
#if COUNT_BBS_AND_INSTRUCTIONS
                instruction_added_count++;
#endif

                for (int i = granule_count; i > 0; i--)
                {                         // 11011001001 000000001 01 00001 00001
                    instrlist_postinsert( // 11011001001 111110000 01 00001 00001
                        dr_bb,
                        instr,
                        INSTR_CREATE_stg(
                            drcontext,
                            reg,
                            reg,
                            OPND_CREATE_INT(1)));
                    inst_added++;
#if COUNT_BBS_AND_INSTRUCTIONS
                    instruction_added_count++;
#endif
                }

                instrlist_postinsert(
                    dr_bb,
                    instr,
                    INSTR_CREATE_irg(
                        drcontext,
                        reg,
                        reg,
                        opnd_create_reg(DR_REG_XZR)));
                inst_added++;
#if COUNT_BBS_AND_INSTRUCTIONS
                instruction_added_count++;
#endif

                gvar->is_tagged = true;
            }

            for (int i = 0; i < inst_added; i++)
            {
                next = instr_get_next(instr);
            }
            app_pc bb_pc = instr_get_app_pc(instr);
            const unsigned long key = map_addr((unsigned long)bb_pc);
#if DEBUG
            dr_printf("BB (instr: %d. 0x%lx) is accessing global variable at address: 0x%lx (ghidra) 0x%lx (target application)\n", i, key, gvar->address, re_map_addr(gvar->address));
            print_bb(drcontext, tag, dr_bb);
#endif
        }
        i++;
    }
#if COUNT_BBS_AND_INSTRUCTIONS
    if (modified)
    {
        bb_modified_count++;
    }
#endif
}

static dr_emit_flags_t tag_memory(
    void *drcontext,
    void *tag,
    instrlist_t *dr_bb,
    bool for_trace,
    bool translating)
{
#if COUNT_BBS_AND_INSTRUCTIONS
    total_bb_count++;
    for (instr_t *instr = instrlist_first_app(dr_bb); instr != NULL;
         instr = instr_get_next_app(instr))
    {

        total_instruction_count++;
    }
#endif

    app_pc bb_pc = instr_get_app_pc(instrlist_first(dr_bb));
    const unsigned long key = map_addr((unsigned long)bb_pc);

#if DEBUG
    dr_printf("BB at 0x%lX\n", key);
#endif

    if (for_trace || translating)
    {
#if VERBOUSE
        dr_printf("// ---- ignore BB at 0x%lX\n", key);
#endif
#if DEBUG
        print_bb(drcontext, tag, dr_bb);
#endif
        return DR_EMIT_DEFAULT;
    }

    DR_ASSERT(parsed_meta != NULL && parsed_meta->main_address > 0);

    if (!main_passed)
    {
        wrap_main(drcontext, dr_bb);
    }

    if (main_passed && parsed_meta->addr_to_bb != NULL)
    {
#if INSTRUMENT_GLOBALS
        instrument_globals(drcontext, tag, dr_bb);
#endif
        Tree *t = parsed_meta->addr_to_bb;
        void *val = search(t, key);
        if (val != NULL)
        {
#if DEBUG
            dr_printf("INFO: BB Before: 0x%lX\n", key);
            print_bb(drcontext, tag, dr_bb);
#endif
            BasicBlock *ghidra_bb = (BasicBlock *)val;
            DR_ASSERT(ghidra_bb != NULL);

#if TAG_FRAME
            tag_frame(
                drcontext,
                tag,
                dr_bb,
                ghidra_bb);
#endif

#if INSTRUMENT_FRAME
            instrument_frame(
                drcontext,
                tag,
                dr_bb,
                ghidra_bb);
#endif

#if ALIGN_STACK
            align_stack(
                drcontext,
                tag,
                dr_bb,
                ghidra_bb);
#endif
#if UNTAG_EPILOG
            untag_in_epilog(
                drcontext,
                dr_bb,
                ghidra_bb);
#endif

#if INSTRUMENT_STACK || INSTRUMENT_FRAME
            instrument_vars(
                drcontext,
                tag,
                dr_bb,
                ghidra_bb);

#endif

#if DEBUG
            dr_printf("INFO Final BB:\n");
            print_bb(drcontext, tag, dr_bb);
#endif
        }
        else
        {
#if DEBUG
            instr_t *last = instrlist_last(dr_bb);
            const unsigned long last_addr = map_addr((unsigned long)instr_get_app_pc(last)) + 3;
            dr_printf("INFO: Ignore BB: 0x%lX - 0x%lX\n", key, last_addr);
#endif
        }
    }

#if DEBUG
    dr_printf("INFO BB:\n");
    print_bb(drcontext, tag, dr_bb);
#endif

    return DR_EMIT_DEFAULT;
}

void print_bb(void *drcontext, void *tag, instrlist_t *dr_bb)
{
    file_t out_file = STDOUT;
    instrlist_disassemble(
        drcontext,
        tag,
        dr_bb,
        out_file);
}

static void event_exit(void)
{
#if COUNT_BBS_AND_INSTRUCTIONS
    dr_printf("MTEI INFO: Executed instructions: %ld\n", total_instruction_count);
    dr_printf("MTEI INFO: Added instructions:    %ld\n", instruction_added_count);
    dr_printf("MTEI INFO: Executed BBs: %ld\n", total_bb_count);
    dr_printf("MTEI INFO: Modified BBs: %ld\n", bb_modified_count);
#endif
    drwrap_exit();
    drmgr_exit();

    // destroy_tree(parsed_meta->addr_to_bb);
    for (int i = 0; i < parsed_meta->globals->globals_count; i++)
    {
        free(parsed_meta->globals->global_variables[i].referee_address);
    }
    free(parsed_meta->globals->global_variables);
    free(parsed_meta->globals);
    free(parsed_meta);
    parsed_meta = NULL;
}
