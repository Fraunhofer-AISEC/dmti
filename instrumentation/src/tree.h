#ifndef TREE_H
#define TREE_H 1

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "dr_api.h"

typedef struct
{
    unsigned long key;
    void *val;
    struct Tree *l, *r;
} Tree;

void *search(Tree *tree, const unsigned long key);

Tree *create_node(Tree *tree, const unsigned long key, void *val);

void insert(Tree *tree, const unsigned long key, void *val);

void rem(Tree *tree, const unsigned long key);

void destroy_tree(Tree *tree);

#endif // TREE_H