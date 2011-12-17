/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "util.h"
#include "hashmap.h"
#include "private.h"

#define NBUCKETS 127

typedef unsigned int (*hash_func_t) (const void *p);
typedef int (*compare_func_t) (const void *a, const void *b);

struct entry {
	const void *key;
	void *value;
	struct entry *next;
};

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

LIB_EXPORT struct l_hashmap *l_hashmap_new(void)
{
	struct l_hashmap *hashmap;

	hashmap = l_new(struct l_hashmap, 1);

	hashmap->hash_func = direct_hash_func;
	hashmap->compare_func = direct_compare_func;
	hashmap->entries = 0;

	return hashmap;
}

LIB_EXPORT void l_hashmap_destroy(struct l_hashmap *hashmap,
				l_hashmap_destroy_func_t destroy)
{
	unsigned int i;

	if (!hashmap)
		return;

	for (i = 0; i < NBUCKETS; i++) {
		struct entry *head = &hashmap->buckets[i];

		if (!head->next || head->next == head)
			continue;

		if (destroy)
			destroy(head->key, head->value);
	}

	l_free(hashmap);
}

LIB_EXPORT bool l_hashmap_insert(struct l_hashmap *hashmap,
				const void *key, void *value)
{
	struct entry *entry, *head;
	unsigned int hash;

	if (!hashmap)
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

LIB_EXPORT void *l_hashmap_remove(struct l_hashmap *hashmap, const void *key)
{
	struct entry *entry, *head, *prev;
	unsigned int hash;

	if (!hashmap)
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

LIB_EXPORT void *l_hashmap_lookup(struct l_hashmap *hashmap, const void *key)
{
	struct entry *entry, *head;
	unsigned int hash;

	if (!hashmap)
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

LIB_EXPORT void l_hashmap_foreach(struct l_hashmap *hashmap,
			l_hashmap_foreach_func_t function, void *user_data)
{
	unsigned int i;

	if (!hashmap || !function)
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

LIB_EXPORT unsigned int l_hashmap_size(struct l_hashmap *hashmap)
{
	if (!hashmap)
		return 0;

	return hashmap->entries;
}

LIB_EXPORT bool l_hashmap_isempty(struct l_hashmap *hashmap)
{
	if (!hashmap)
		return true;

	return hashmap->entries == 0;
}
