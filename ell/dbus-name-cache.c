/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2016  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>

#include "util.h"
#include "hashmap.h"
#include "dbus.h"
#include "dbus-private.h"

struct _dbus_name_cache {
	struct l_dbus *bus;
	struct l_hashmap *names;
	const struct _dbus_name_ops *driver;
};

struct name_cache_entry {
	int ref_count;
	char *unique_name;
};

struct _dbus_name_cache *_dbus_name_cache_new(struct l_dbus *bus,
					const struct _dbus_name_ops *driver)
{
	struct _dbus_name_cache *cache;

	cache = l_new(struct _dbus_name_cache, 1);

	cache->bus = bus;
	cache->driver = driver;

	return cache;
}

static void name_cache_entry_destroy(void *data)
{
	struct name_cache_entry *entry = data;

	l_free(entry->unique_name);

	l_free(entry);
}

void _dbus_name_cache_free(struct _dbus_name_cache *cache)
{
	l_hashmap_destroy(cache->names, name_cache_entry_destroy);

	l_free(cache);
}

bool _dbus_name_cache_add(struct _dbus_name_cache *cache, const char *name)
{
	struct name_cache_entry *entry;

	if (!_dbus_valid_bus_name(name))
		return false;

	if (!cache->names)
		cache->names = l_hashmap_string_new();

	entry = l_hashmap_lookup(cache->names, name);

	if (!entry) {
		entry = l_new(struct name_cache_entry, 1);

		l_hashmap_insert(cache->names, name, entry);

		cache->driver->get_name_owner(cache->bus, name);
	}

	entry->ref_count++;

	return true;
}

bool _dbus_name_cache_remove(struct _dbus_name_cache *cache, const char *name)
{
	struct name_cache_entry *entry;

	entry = l_hashmap_lookup(cache->names, name);

	if (!entry)
		return false;

	if (--entry->ref_count)
		return true;

	l_hashmap_remove(cache->names, name);

	name_cache_entry_destroy(entry);

	return true;
}

const char *_dbus_name_cache_lookup(struct _dbus_name_cache *cache,
					const char *name)
{
	struct name_cache_entry *entry;

	entry = l_hashmap_lookup(cache->names, name);

	if (!entry)
		return NULL;

	return entry->unique_name;
}

void _dbus_name_cache_notify(struct _dbus_name_cache *cache,
				const char *name, const char *owner)
{
	struct name_cache_entry *entry;

	if (_dbus_parse_unique_name(name, NULL))
		return;

	entry = l_hashmap_lookup(cache->names, name);

	if (!entry)
		return;

	l_free(entry->unique_name);

	entry->unique_name = (owner && *owner != '\0') ? l_strdup(owner) : NULL;
}
