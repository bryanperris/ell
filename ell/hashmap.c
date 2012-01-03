/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2012  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License version 2.1 as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "util.h"
#include "hashmap.h"
#include "private.h"

/**
 * SECTION:hashmap
 * @short_description: Hash table support
 *
 * Hash table support
 */

#define NBUCKETS 127

typedef unsigned int (*hash_func_t) (const void *p);
typedef int (*compare_func_t) (const void *a, const void *b);

struct entry {
	const void *key;
	void *value;
	struct entry *next;
};

/**
 * l_hashmap:
 *
 * Opague object representing the hash table.
 */
struct l_hashmap {
	hash_func_t hash_func;
	compare_func_t compare_func;
	unsigned int entries;
	struct entry buckets[NBUCKETS];
};

static unsigned int direct_hash_func(const void *p)
{
	return L_PTR_TO_UINT(p);
}

static int direct_compare_func(const void *a, const void *b)
{
        return a < b ? -1 : (a > b ? 1 : 0);
}

/**
 * l_hashmap_new:
 *
 * Create a new hash table.
 *
 * No error handling is needed since. In case of real memory allocation
 * problems abort() will be called.
 *
 * Returns: a newly allocated #l_hashmap object
 **/
LIB_EXPORT struct l_hashmap *l_hashmap_new(void)
{
	struct l_hashmap *hashmap;

	hashmap = l_new(struct l_hashmap, 1);

	hashmap->hash_func = direct_hash_func;
	hashmap->compare_func = direct_compare_func;
	hashmap->entries = 0;

	return hashmap;
}

/**
 * l_hashmap_destroy:
 * @hashmap: hash table object
 * @destroy: destroy function
 *
 * Free hash table and call @destory on all remaining entries.
 **/
LIB_EXPORT void l_hashmap_destroy(struct l_hashmap *hashmap,
				l_hashmap_destroy_func_t destroy)
{
	unsigned int i;

	if (unlikely(!hashmap))
		return;

	for (i = 0; i < NBUCKETS; i++) {
		struct entry *entry, *head = &hashmap->buckets[i];

		if (!head->next)
			continue;

		for (entry = head;; entry = entry->next) {
			if (destroy)
				destroy(entry->key, entry->value);

			if (entry->next == head)
				break;
		}
	}

	l_free(hashmap);
}

/**
 * l_hashmap_insert:
 * @hashmap: hash table object
 * @key: key pointer
 * @value: value pointer
 *
 * Insert new @value entry with @key.
 *
 * Returns: #true when value has been added and #false in case of failure
 **/
LIB_EXPORT bool l_hashmap_insert(struct l_hashmap *hashmap,
				const void *key, void *value)
{
	struct entry *entry, *head;
	unsigned int hash;

	if (unlikely(!hashmap))
		return false;

	hash = hashmap->hash_func(key) % NBUCKETS;
	head = &hashmap->buckets[hash];

	if (!head->next) {
		head->key = key;
		head->value = value;
		head->next = head;
		goto done;
	}

	entry = l_new(struct entry, 1);

	entry->key = key;
	entry->value = value;
	entry->next = head;

	while (head->next != entry->next)
		head = head->next;

	head->next = entry;

done:
	hashmap->entries++;

	return true;
}

/**
 * l_hashmap_remove:
 * @hashmap: hash table object
 * @key: key pointer
 *
 * Remove entry for @key.
 *
 * Returns: value pointer of the removed entry or #NULL in case of failure
 **/
LIB_EXPORT void *l_hashmap_remove(struct l_hashmap *hashmap, const void *key)
{
	struct entry *entry, *head, *prev;
	unsigned int hash;

	if (unlikely(!hashmap))
		return NULL;

	hash = hashmap->hash_func(key) % NBUCKETS;
	head = &hashmap->buckets[hash];

	if (!head->next)
		return NULL;

	for (entry = head, prev = NULL;; prev = entry, entry = entry->next) {
		void *value;

		if (hashmap->compare_func(key, entry->key))
			continue;

		value = entry->value;

		if (entry == head) {
			if (entry->next == head) {
				head->key = NULL;
				head->value = NULL;
				head->next = NULL;
			} else {
				entry = entry->next;
				head->key = entry->key;
				head->value = entry->value;
				head->next = entry->next;
				l_free(entry);
			}
		} else {
			prev->next = entry->next;
			l_free(entry);
		}

		hashmap->entries--;

		return value;
        }

	return NULL;
}

/**
 * l_hashmap_lookup:
 * @hashmap: hash table object
 * @key: key pointer
 *
 * Lookup entry for @key.
 *
 * Returns: value pointer for @key or #NULL in case of failure
 **/
LIB_EXPORT void *l_hashmap_lookup(struct l_hashmap *hashmap, const void *key)
{
	struct entry *entry, *head;
	unsigned int hash;

	if (unlikely(!hashmap))
		return NULL;

	hash = hashmap->hash_func(key) % NBUCKETS;
	head = &hashmap->buckets[hash];

	if (!head->next)
		return NULL;

	for (entry = head;; entry = entry->next) {
		if (!hashmap->compare_func(key, entry->key))
			return entry->value;

		if (entry->next == head)
			break;
	}

	return NULL;
}

/**
 * l_hashmap_foreach:
 * @hashmap: hash table object
 * @function: callback function
 * @user_data: user data given to callback function
 *
 * Call @function for every entry in @hashmap.
 **/
LIB_EXPORT void l_hashmap_foreach(struct l_hashmap *hashmap,
			l_hashmap_foreach_func_t function, void *user_data)
{
	unsigned int i;

	if (unlikely(!hashmap || !function))
		return;

	for (i = 0; i < NBUCKETS; i++) {
		struct entry *entry, *head = &hashmap->buckets[i];

		if (!head->next)
			continue;

		for (entry = head;; entry = entry->next) {
			function(entry->key, entry->value, user_data);

			if (entry->next == head)
				break;
		}
	}
}

/**
 * l_hashmap_size:
 * @hashmap: hash table object
 *
 * Returns: entries in the hash table
 **/
LIB_EXPORT unsigned int l_hashmap_size(struct l_hashmap *hashmap)
{
	if (unlikely(!hashmap))
		return 0;

	return hashmap->entries;
}

/**
 * l_hashmap_isempty:
 * @hashmap: hash table object
 *
 * Returns: #true if hash table is empty and #false if not
 **/
LIB_EXPORT bool l_hashmap_isempty(struct l_hashmap *hashmap)
{
	if (unlikely(!hashmap))
		return true;

	return hashmap->entries == 0;
}
