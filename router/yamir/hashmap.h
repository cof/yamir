#ifndef _HASHMAP_H_
#define _HASHMAP_H_

/* hashmap api */
struct inthash_entry {
    struct inthash_entry *next;
    uint32_t key;
    void *data;
};

struct inthash_table {
    int size;
    struct inthash_entry **array;
};

extern void *inthash_table_lookup(struct inthash_table *table, uint32_t key);
extern void inthash_table_del(struct inthash_table *table, uint32_t key);
extern void inthash_table_add(struct inthash_table *table, uint32_t key, void *data);
extern void inthash_table_free(struct inthash_table *table);
extern struct inthash_table *inthash_table_create(int size);

#endif
