#include <stdlib.h>
#include <stdint.h>
#include"structs.h"

typedef struct
{
    f_tuple key; // key is NULL if this slot is empty
    connection *value;
} ht_entry;

// Hash table structure: create with ht_create, free with ht_destroy.
typedef struct
{
    ht_entry *entries; // hash slots
    size_t capacity;   // size of _entries array
    size_t length;     // number of items in hash table
} ht;

typedef struct
{
    f_tuple *key; // current key
    connection *value;     // current value

    // Don't use these fields directly.
    ht *_table;    // reference to hash table being iterated
    size_t _index; // current index into ht._entries
} hti;

ht *ht_create(void);
void ht_destroy(ht *table);
connection *ht_get(ht *table, f_tuple *key);
connection *ht_set(ht *table, f_tuple *key,connection *value);
static connection *ht_set_entry(ht *table,ht_entry *entries, size_t capacity, f_tuple *key,connection *value, size_t *plength);
void ht_reset(ht *table);
int f_hash(f_tuple key);
int check_key(f_tuple *tuple1,f_tuple tuple2);
int check_entry(ht_entry entry);