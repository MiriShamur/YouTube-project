#include "hashtable.h"
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define FNV_OFFSET 14695981039346656037UL
#define FNV_PRIME 1099511628211UL
#define INITIAL_CAPACITY 1000

ht *ht_create(void)
{
    // Allocate space for hash table struct.
    ht *table = (ht *)malloc(sizeof(ht));
    if (table == NULL)
    {
        return NULL;
    }
    table->length = 0;
    table->capacity = INITIAL_CAPACITY;

    // Allocate (zero'd) space for entry buckets.
    table->entries = (ht_entry *)calloc(table->capacity, sizeof(ht_entry));
    if (table->entries == NULL)
    {
        free(table); // error, free table before we return!
        return NULL;
    }
    return table;
}
connection *ht_get(ht *table, f_tuple *key)
{
    // AND hash with capacity-1 to ensure it's within entries array.
    int hash = f_hash(*key);
    size_t index = (size_t)(hash & (uint64_t)(table->capacity - 1));
    // Loop till we find an empty entry.
    while (table->entries[index].key.client_ip != 0)
    {
        if (check_key(key, table->entries[index].key))
        {
            // Found key, return value.
            printf("index: %ld\n", index);
            return table->entries[index].value;
        }
        // Key wasn't in this slot, move to next (linear probing).
        index++;
        if (index >= table->capacity)
        {
            // At end of entries array, wrap around.
            index = 0;
        }
    }
    return NULL;
}

// Internal function to set an entry (without expanding table).
static connection *ht_set_entry(ht *table, ht_entry *entries, size_t capacity, f_tuple *key, connection *value, size_t *plength)
{
    // AND hash with capacity-1 to ensure it's within entries array.
    int hash = f_hash(*key);
    size_t index = (size_t)(hash & (uint64_t)(table->capacity - 1));
    // Loop till we find an empty entry.
    while (entries[index].key.client_ip != 0)
    {
        if (check_key(key, entries[index].key) == 1)
        {
            // Found key (it already exists), update value.
            entries[index].value = value;

            return *(&entries[index].value);
        }
        // Key wasn't in this slot, move to next (linear probing).
        index++;
        if (index >= capacity)
        {
            // At end of entries array, wrap around.
            index = 0;
        }
    }
    // Didn't find key, allocate+copy if needed, then insert it.
    if (plength != NULL)
    {
        (*plength)++;
    }
    entries[index].key = *key;
    entries[index].value = value;

    return value;
}

// Expand hash table to twice its current size. Return true on success,
// false if out of memory.
static int ht_expand(ht *table)
{
    // Allocate new entries array.
    size_t new_capacity = table->capacity * 2;
    if (new_capacity < table->capacity)
    {
        return 0; // overflow (capacity would be too big)
    }
    ht_entry *new_entries = (ht_entry *)calloc(new_capacity, sizeof(ht_entry));
    if (new_entries == NULL)
    {
        return 0;
    }
    // Iterate entries, move all non-empty ones to new table's entries.
    for (size_t i = 0; i < table->capacity; i++)
    {
        ht_entry entry = table->entries[i];
        if (&entry.key != NULL)
        {
            ht_set_entry(table, new_entries, new_capacity, &entry.key,
                         entry.value, NULL);
        }
    }
    // Free old entries array and update this table's details.
    free(table->entries);
    table->entries = new_entries;
    table->capacity = new_capacity;
    return 1;
}

connection *ht_set(ht *table, f_tuple *key, connection *value)
{
    assert(value != NULL);
    if (value == NULL)
    {
        return NULL;
    }
    // If length will exceed half of current capacity, expand it.
    if (table->length >= table->capacity / 2)
    {
        if (!ht_expand(table))
        {
            return NULL;
        }
    }
    // Set entry and update length.
    return ht_set_entry(table, table->entries, table->capacity, value->trans->tuple, value,
                        &table->length);
}

int f_hash(f_tuple key)
{
    return (int)((size_t)(key.client_ip) * 59) ^
           ((size_t)(key.server_ip)) ^
           ((size_t)(key.client_port) << 16) ^
           ((size_t)(key.server_port)) ^
           ((size_t)(key.protocol));
}

int check_key(f_tuple *tuple1, f_tuple tuple2)
{
    return (tuple1->client_ip == tuple2.client_ip &&
            tuple1->server_ip == tuple2.server_ip &&
            tuple1->client_port == tuple2.client_port &&
            tuple1->server_port == tuple2.server_port)
               ? 1
               : -1;
}