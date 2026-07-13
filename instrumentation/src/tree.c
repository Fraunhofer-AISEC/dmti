#include "tree.h"


Tree *get_next(Tree *tree, const unsigned long key)
{
    DR_ASSERT(tree != NULL);
    return key < tree->key
               ? (Tree *)(tree->l)
               : (Tree *)(tree->r);
}

void *search(Tree *tree, const unsigned long key)
{
#if DEBUG
    dr_printf("Start Search Tree: %p\n", tree);
    dr_printf("     key: %lx =? %lx\n", tree->key, key);
#endif

    while (tree != NULL && tree->key != key)
    {
        tree = get_next(tree, key);
    }
    if (tree == NULL)
    {
        return NULL;
    }
    else
    {
#if DEBUG
        dr_printf("Tree: %p\n", tree);
        dr_printf("     key: %lx -> %p\n", tree->key, tree->val);
#endif
        return tree->val;
    }
}

Tree *create_node(Tree *tree, const unsigned long key, void *val)
{ // create node (sub tree)

#if DEBUG
    dr_printf("INFO: create node for: %lX\n", key);
#endif

    DR_ASSERT(val != NULL);
    Tree *node_ptr = malloc(sizeof(Tree));

#if DEBUG
    dr_printf("INFO: node_ptr %p\n", node_ptr);
#endif

    if (tree == node_ptr)
    {
        dr_printf("WARNING: reallocating node!!\n");
        node_ptr = malloc(sizeof(Tree));
    }

    DR_ASSERT(node_ptr != NULL);
    DR_ASSERT(tree != node_ptr);

    node_ptr->key = key;
    node_ptr->val = val;
    node_ptr->l = NULL;
    node_ptr->r = NULL;
    return node_ptr;
}

void insert(Tree *tree, const unsigned long key, void *val)
{
    DR_ASSERT(tree != NULL && val != NULL);

#if DEBUG
    dr_printf("INFO: inserting Tree (%p: K %lX, l %p, r %p) Key: %lX, value: %ld\n", tree, tree->key, tree->l, tree->r, key, val);
#endif

    if (tree->key == key) // key aleready exists
    {                     // Update Value
#if DEBUG
        dr_printf("INFO: update Key: %lX, value: %ld\n", key, val);
#endif
        tree->val = val;
    }
    else
    {
        Tree *next = get_next(tree, key);
        if (next == NULL)
        { // Create new node
#if DEBUG
            dr_printf("INFO: create node for Key: %lX, value: %ld\n", key, val);
#endif
            struct Tree *t = (struct Tree *)create_node(tree, key, val);
            DR_ASSERT(t != NULL);
            if (key < tree->key)
            {
                tree->l = t;
            }
            else
            {
                tree->r = t;
            }
        }
        else
        { // recursive call
            insert(next, key, val);
        }
    }
}

void remove_next(Tree *parent, Tree *to_replace, const unsigned long key)
{
    DR_ASSERT(to_replace->key == key);
    Tree *toFree = to_replace;
    Tree *next;
    if (to_replace->l == NULL)
    {
        next = (Tree *)to_replace->r;
    }
    else
    {
        next = (Tree *)to_replace->l;

        if (next->r == NULL)
        {
            next->r = (struct Tree *)to_replace->r;
        }
        else
        {
            Tree *r = (Tree *)next;
            while (r->r != NULL)
            {
                r = (Tree *)r->r;
            }
            r->r = to_replace->r;
        }
    }
    if (parent->key < key)
    {
        parent->r = (struct Tree *)next;
    }
    else
    {
        parent->l = (struct Tree *)next;
    }
    to_replace->l = NULL;
    to_replace->r = NULL;
    free(to_replace->val);
    free(to_replace);
}

void rem(Tree *tree, const unsigned long key)
{
    if (tree != NULL)
    {
        Tree *next = get_next(tree, key);
        if (next != NULL)
        {
            if (next->key == key)
            {
                remove_next(tree, next, key);
            }
            else
            {
                rem(next, key);
            }
        }
    }
}

void destroy_tree(Tree *tree)
{
    if (tree != NULL)
    {
        destroy_tree((Tree *)tree->l);
        destroy_tree((Tree *)tree->r);
        free(tree);
    }
}
