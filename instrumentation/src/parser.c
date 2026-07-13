#include "parser.h"

void assertNotNullAndEqKey(cJSON *c_json_struc, char *key)
{
    bool is_null = c_json_struc == NULL;
    if (is_null)
    {
        dr_printf("ERROR relating cJSON struct is null for key: %s\n", key);
    }
    DR_ASSERT_MSG(
        !is_null,
        "The c_json_struc should not be null.");
    bool has_name = strcmp(c_json_struc->string, key) == 0;
    if (!has_name)
    {
        dr_printf("ERROR relating cJSON struct does not contin the key: \"%s\"\n", key);
    }
    DR_ASSERT_MSG(
        has_name,
        "The c_json_struc should contain the specified key.");
}

long *get_usages(cJSON *usages, int usage_count)
{
    long *uses = (long *)malloc(sizeof(long) * usage_count);
    cJSON *usage_iter = usages;
    for (int i = 0; i < usage_count; i++)
    {
        DR_ASSERT_MSG(usage_iter != NULL, "The usage references should not be null");
        uses[i] = strtol(cJSON_GetStringValue(usage_iter), NULL, HEX_BASE);
        usage_iter = usage_iter->next;
    }
    return uses;
}

Variable *get_variables(cJSON *variables, int var_count)
{
    Variable *vars = (Variable *)malloc(sizeof(Variable) * var_count);
    DR_ASSERT_MSG(vars != NULL, "Insufficient memory available for malloc Variables");

    cJSON *var_iter = variables;
    for (int i = 0; i < var_count; i++)
    {
        cJSON *var = var_iter->child;
        assertNotNullAndEqKey(var, "variable_name");
        cJSON *data_type = var->next;
        assertNotNullAndEqKey(data_type, "data_type");
        cJSON *min_address = data_type->next;
        assertNotNullAndEqKey(min_address, "min_address");
        cJSON *first_use_offset = min_address->next;
        assertNotNullAndEqKey(first_use_offset, "first_use_offset");
        cJSON *storage = first_use_offset->next;
        assertNotNullAndEqKey(storage, "storage");
        cJSON *size = storage->next;
        assertNotNullAndEqKey(size, "size");
        cJSON *is_stack_variable = size->next;
        assertNotNullAndEqKey(is_stack_variable, "is_stack_variable");
        cJSON *is_memory_variable = is_stack_variable->next;
        assertNotNullAndEqKey(is_memory_variable, "is_memory_variable");
        cJSON *is_register_variable = is_memory_variable->next;
        assertNotNullAndEqKey(is_register_variable, "is_register_variable");
        cJSON *is_valid = is_register_variable->next;
        assertNotNullAndEqKey(is_valid, "is_valid");
        cJSON *stack_offset = is_valid->next;
        assertNotNullAndEqKey(stack_offset, "stack_offset");
        cJSON *references = stack_offset->next;
        assertNotNullAndEqKey(references, "references");
        cJSON *ptrs = references->next;
        assertNotNullAndEqKey(ptrs, "ptrs");

        Variable *v = &(vars[i]);
        v->is_instrumented = false;
        v->is_memory_variable = strcmp(cJSON_GetStringValue(is_memory_variable), "true");
        v->is_Register_variable = strcmp(cJSON_GetStringValue(is_register_variable), "true");
        v->is_stack_variable = strcmp(cJSON_GetStringValue(is_stack_variable), "true");
        v->stack_offset = strtol(cJSON_GetStringValue(stack_offset), NULL, DEZ_BASE);
        v->size = strtol(cJSON_GetStringValue(size), NULL, DEZ_BASE);
        v->usage_count = cJSON_GetArraySize(references);
        v->usages = get_usages(references->child, v->usage_count);
#if ALIGN_STACK
        v->access_count = cJSON_GetArraySize(ptrs);
        v->accesses = get_usages(ptrs->child, v->access_count);
#endif
        var_iter = var_iter->next;
    }
    return vars;
}

BasicBlock *set_bb_data(cJSON *func, ParsedMeta *result)
{
    assertNotNullAndEqKey(func, "function_name");
    cJSON *calling_convention = func->next;
    assertNotNullAndEqKey(calling_convention, "calling_convention");
    cJSON *start_address = calling_convention->next;
    assertNotNullAndEqKey(start_address, "start_address");
    cJSON *end_address = start_address->next;
    assertNotNullAndEqKey(end_address, "end_address");
    cJSON *stack_size = end_address->next;
    assertNotNullAndEqKey(stack_size, "stack_size");
    cJSON *prolog_len = stack_size->next;
    assertNotNullAndEqKey(prolog_len, "prolog_len");
    cJSON *epilog_len = prolog_len->next;
    assertNotNullAndEqKey(epilog_len, "epilog_len");
    cJSON *variables = epilog_len->next;
    assertNotNullAndEqKey(variables, "variables");
    cJSON *basic_blocks = variables->next;
    assertNotNullAndEqKey(basic_blocks, "basic_blocks");

    Function *function = (Function *)malloc(sizeof(Function));
    DR_ASSERT_MSG(function != NULL, "Insufficient memory available for malloc Functions");
    function->start_address = strtol(cJSON_GetStringValue(start_address), NULL, HEX_BASE);
    function->end_address = strtol(cJSON_GetStringValue(end_address), NULL, HEX_BASE);
    function->stack_size = strtol(cJSON_GetStringValue(stack_size), NULL, DEZ_BASE);
    function->prolog_len = strtol(cJSON_GetStringValue(prolog_len), NULL, DEZ_BASE);
    function->epilog_len = strtol(cJSON_GetStringValue(epilog_len), NULL, DEZ_BASE);
    function->var_count = cJSON_GetArraySize(variables);
    function->vars = get_variables(variables->child, function->var_count);

    cJSON *bb_iter = basic_blocks->child;
    while (bb_iter != NULL)
    {
        cJSON *bb_name = bb_iter->child;
        assertNotNullAndEqKey(bb_name, "bb_name");
        cJSON *start_address = bb_name->next;
        assertNotNullAndEqKey(start_address, "start_address");
        cJSON *end_address = start_address->next;
        DR_ASSERT_MSG(end_address, "end_address");

        BasicBlock *bb = (BasicBlock *)malloc(sizeof(BasicBlock));
        DR_ASSERT_MSG(bb != NULL, "Insufficient memory available for malloc BasicBlocks");
        bb->start_address = strtol(cJSON_GetStringValue(start_address), NULL, HEX_BASE);
        bb->end_address = strtol(cJSON_GetStringValue(end_address), NULL, HEX_BASE);
        bb->function = function;

        char *bb_start_address = cJSON_GetStringValue(start_address);
        const unsigned long key = strtoul(bb_start_address, NULL, HEX_BASE);
        void *val = (void *)bb;
        DR_ASSERT(key > 0 && val != NULL);
        if (result->addr_to_bb == NULL)
        {
            result->addr_to_bb = create_node(NULL, key, val);
        }
        else
        {
            insert(result->addr_to_bb, key, val);
        }
        DR_ASSERT(result->addr_to_bb != NULL);

        bb_iter = bb_iter->next;
    }
}

char *read_file(const char *file_name)
{
    // Read input file
    struct stat *stats = malloc(sizeof(struct stat));
    int can_read_file_stats = stat(file_name, stats);
    DR_ASSERT_MSG(
        can_read_file_stats == 0,
        "Cannot get gile properties.\nProvided file probably does not exist!");
    DR_ASSERT_MSG(
        stats != NULL,
        "Cannot get gile properties.");
    DR_ASSERT_MSG(
        stats->st_mode & R_OK,
        "The provided file is not readable");
    DR_ASSERT_MSG(
        stats->st_size != 0,
        "stats->st_size should not be null");

    const int buf_size = stats->st_size + 1;
    free(stats);
    const int nmemb = sizeof(char);
    char *file_buf = (char *)calloc(nmemb, buf_size);

    FILE *in_file = fopen(file_name, "rb");
    const bool is_file_null = in_file == NULL;
    DR_ASSERT_MSG(
        !is_file_null,
        "Cannot open file.");
    const size_t read_elements = fread(
        file_buf,
        nmemb,
        buf_size,
        in_file);
    bool corect_byte_count_read = read_elements == buf_size - 1;
    DR_ASSERT_MSG(
        corect_byte_count_read,
        "An error occured during file read.");

    file_buf[buf_size - 1] = 0; // force zero termination (should be useless but who konws)
    return file_buf;
}

int get_bb_count(cJSON *functions)
{
    int bb_count = 0;
    cJSON *function_iter = functions;
    while (function_iter != NULL)
    {
        cJSON *basic_blocks = cJSON_GetObjectItem(function_iter, "basic_blocks");
        assertNotNullAndEqKey(basic_blocks, "basic_blocks");

        bb_count += cJSON_GetArraySize(basic_blocks);
        function_iter = function_iter->next;
    }
    return bb_count;
}

Globals *parse_globals(cJSON *globals_json)
{
    DR_ASSERT_MSG(
        globals_json != NULL,
        "The gloabls should not be null.");
    assertNotNullAndEqKey(globals_json, "global_variables");
    unsigned int globals_count = (unsigned int)cJSON_GetArraySize(globals_json);

    Globals *globals = malloc(sizeof(Globals));
    globals->globals_count = globals_count;
    globals->global_variables = malloc(sizeof(GlobalVariable) * globals_count);

    unsigned int index = 0;
    cJSON *global_iter = globals_json->child;

    while (index < globals_count && global_iter != NULL)
    {
        GlobalVariable *global = &(globals->global_variables[index]);
        global->is_tagged = false;
        cJSON *addr = global_iter->child;
        assertNotNullAndEqKey(addr, "address");
        global->address = strtol(cJSON_GetStringValue(addr), NULL, HEX_BASE);
        cJSON *size = addr->next;
        assertNotNullAndEqKey(size, "size");
        global->size = strtol(cJSON_GetStringValue(size), NULL, DEZ_BASE);
        cJSON *mem_block = size->next;
        assertNotNullAndEqKey(mem_block, "memory_block");
        cJSON *references = mem_block->next;
        assertNotNullAndEqKey(references, "references");

        unsigned int referenc_count = (unsigned int)cJSON_GetArraySize(references);
        global->referee_count = referenc_count;
        global->referee_address = malloc(sizeof(unsigned long) * referenc_count);
        unsigned int reference_index = 0;
        cJSON *referenc_iter = references->child;

        while (reference_index < referenc_count && referenc_iter != NULL)
        {
            unsigned long reference = strtol(cJSON_GetStringValue(referenc_iter), NULL, HEX_BASE);
            global->referee_address[reference_index] = reference;

            referenc_iter = referenc_iter->next;
            reference_index++;
        }
        DR_ASSERT_MSG(
            referenc_iter == NULL && reference_index == referenc_count,
            "An Error happend while parsing the references of the Globals.");

        global_iter = global_iter->next;
        index++;
    }
    DR_ASSERT_MSG(
        global_iter == NULL && index == globals_count,
        "An Error happend while parsing the Globals.");
    return globals;
}

ParsedMeta *parse_file(const char *file_name)
{
    ParsedMeta *result = malloc(sizeof(ParsedMeta));
    result->addr_to_bb = NULL;

    char *file_buf = read_file(file_name);
    // Parse JSON
    cJSON *json = cJSON_Parse(file_buf);
    free(file_buf);

    const bool json_non_null = json != NULL;
    if (!json_non_null)
    {
        const char *error_ptr = cJSON_GetErrorPtr();
    }
    DR_ASSERT_MSG(
        json_non_null,
        "Unable to parse the provided file!");

    // Store in local Data structure
    cJSON *meta_data = json->child;
    DR_ASSERT_MSG(
        meta_data != NULL,
        "The meta_data should not be null.");
    cJSON *main_address_json = meta_data->child;
    assertNotNullAndEqKey(main_address_json, "main_address");
    result->main_address = strtol(cJSON_GetStringValue(main_address_json), NULL, HEX_BASE);

    cJSON *prob_globals = meta_data->next;
    DR_ASSERT_MSG(
        prob_globals != NULL,
        "The provided json file should contain global variable information.");
    result->globals = parse_globals(prob_globals);

    cJSON *prob_functions = prob_globals->next;
    DR_ASSERT_MSG(
        prob_functions != NULL,
        "The provided json file should contain function information.");
    cJSON *functions = prob_functions->child;
#if DEBUG
    char *functions_string = cJSON_Print(functions);
#endif

    cJSON *function_iter = functions;
    while (function_iter != NULL)
    {
        set_bb_data(function_iter->child, result);
        function_iter = function_iter->next;
    }

    cJSON_Delete(json);

    return result;
}
