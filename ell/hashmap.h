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

#ifndef __ELL_HASHMAP_H
#define __ELL_HASHMAP_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*l_hashmap_foreach_func_t) (const void *key, void *value,
							void *user_data);
typedef void (*l_hashmap_destroy_func_t) (const void *key, void *value);

struct l_hashmap;

struct l_hashmap *l_hashmap_new(void);
void l_hashmap_destroy(struct l_hashmap *hashmap,
			l_hashmap_destroy_func_t destroy);

bool l_hashmap_insert(struct l_hashmap *hashmap,
			const void *key, void *value);
void *l_hashmap_remove(struct l_hashmap *hashmap, const void *key);
void *l_hashmap_lookup(struct l_hashmap *hashmap, const void *key);

void l_hashmap_foreach(struct l_hashmap *hashmap,
			l_hashmap_foreach_func_t function, void *user_data);

unsigned int l_hashmap_size(struct l_hashmap *hashmap);
bool l_hashmap_isempty(struct l_hashmap *l_hashmap);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_HASHMAP_H */
