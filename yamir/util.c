#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>

#include <sys/time.h>
#include <sys/types.h>

#include "util.h"

#define hashsize(n) ((uint32_t)1<<(n))
#define hashmask(n) (hashsize(n)-1)

// jenkins hash
static uint32_t make_hash(uint32_t a, int size)
{
    a = (a+0x7ed55d16) + (a<<12);
    a = (a^0xc761c23c) ^ (a>>19);
    a = (a+0x165667b1) + (a<<5);
    a = (a+0xd3a2646c) ^ (a<<9);
    a = (a+0xfd7046c5) + (a<<3);
    a = (a^0xb55a4f09) ^ (a>>16);

    return a & hashmask(size);
}

static struct inthash_entry *find_entry(struct inthash_entry *head, uint32_t key)
{
    struct inthash_entry *entry;

    for (entry=head; entry != NULL; entry=entry->next) {
        if (entry->key == key) {
            return entry;
        }
    }

    return NULL;
}

void *inthash_table_lookup(struct inthash_table *table, uint32_t key)
{
    uint32_t hash;
    struct inthash_entry *entry;

    hash = make_hash(key, table->size);
    entry = find_entry(table->array[hash], key);
    if (entry) {
        return entry->data;
    }
    return NULL;
}

void inthash_table_del(struct inthash_table *table, uint32_t key)
{
    uint32_t hash;
    struct inthash_entry *entry, *prev;

    // need to find elem and its previous entry
    hash = make_hash(key, table->size);
    entry = table->array[hash];
    prev = NULL;
    while (entry && entry->key != key) {
        prev = entry;
        entry = entry->next;
    } 

    if (entry) {
        if (prev) {
            prev->next = entry->next;
        }
        else {
            table->array[hash] = entry->next;
        }
        entry->next = NULL;
        free(entry);
    }
}

void inthash_table_add(struct inthash_table *table, uint32_t key, void *data)
{
    uint32_t hash;
    struct inthash_entry *entry;

    hash = make_hash(key, table->size);

    entry = find_entry(table->array[hash], key);
    if (entry != NULL) {
        fprintf(stderr, "inthash_table_add(%d) key already exists!\n", key);
        abort();
    }

    entry = malloc(sizeof(*entry));
    entry->key = key;
    entry->data = data;
    entry->next = table->array[hash];
    table->array[hash] = entry;
}

void inthash_table_free(struct inthash_table *table)
{
    // TODO
}

struct inthash_table *inthash_table_create(int size)
{
    struct inthash_table *table;

    table = malloc(sizeof(*table));
    table->size = size;
    table->array = calloc(size, sizeof(struct inthash_entry *));
    if (table->array == NULL) {
        fprintf(stderr,"calloc(%d) failed\n", size);
        abort();
    }

    return table;
}

