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

#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <glob.h>

#include "util.h"
#include "queue.h"
#include "plugin.h"
#include "private.h"

/**
 * SECTION:plugin
 * @short_description: Plugin framework
 *
 * Plugin framework
 */

/**
 * l_plugin_desc:
 *
 * Plugin descriptor.
 */

static struct l_queue *plugin_list;

struct plugin {
	void *handle;
	bool active;
	const struct l_plugin_desc *desc;
};

static void plugin_destroy(void *user_data)
{
	struct plugin *plugin = user_data;

	if (plugin->active && plugin->desc->exit)
		plugin->desc->exit();

	if (plugin->handle)
		dlclose(plugin->handle);

	l_free(plugin);
}

static int compare_priority(const void *a, const void *b, void *user_data)
{
	const struct plugin *plugin_a = a;
	const struct plugin *plugin_b = b;

	return plugin_a->desc->priority - plugin_b->desc->priority;
}

static bool plugin_add(void *handle, const struct l_plugin_desc *desc,
							const char *version)
{
	struct plugin *plugin;

	if (!desc->init)
		return false;

	if (version) {
		if (!desc->version)
			return false;

		if (strcmp(desc->version, version))
			return false;
	}

	plugin = l_new(struct plugin, 1);

	plugin->handle = handle;
	plugin->active = false;
	plugin->desc = desc;

	l_queue_insert(plugin_list, plugin, compare_priority, NULL);

	return true;
}

static void plugin_start(void *data, void *user_data)
{
	struct plugin *plugin = data;

	if (plugin->desc->init() < 0)
		return;

	plugin->active = true;
}

/**
 * l_plugin_add:
 * @desc: plugin description record
 * @version: version string or #NULL
 *
 * Adds plugin description.
 **/
LIB_EXPORT void l_plugin_add(const struct l_plugin_desc *desc,
						const char *version)
{
	if (!plugin_list)
		plugin_list = l_queue_new();

	if (!desc)
		return;

	plugin_add(NULL, desc, version);
}

/**
 * l_plugin_load:
 * @pattern: file pattern
 * @symbol: plugin descriptor symbol
 * @version: version string or #NULL
 *
 * Loads plugins from @pattern location and execute @symbol plugin descriptor.
 **/
LIB_EXPORT void l_plugin_load(const char *pattern, const char *symbol,
							const char *version)
{
	glob_t gl;
	size_t i;

	if (!plugin_list)
		plugin_list = l_queue_new();

	if (!pattern || !symbol)
		goto done;

	if (glob(pattern, GLOB_NOSORT, NULL, &gl))
		goto done;

	for (i = 0; i < gl.gl_pathc; i++) {
		void *handle;
		struct l_plugin_desc *desc;

		handle = dlopen(gl.gl_pathv[i], RTLD_NOW);
		if (!handle)
			continue;

		desc = dlsym(handle, symbol);
		if (!desc) {
			dlclose(handle);
			continue;
		}

		if (!plugin_add(handle, desc, version))
			dlclose(handle);
	}

	globfree(&gl);

done:
	l_queue_foreach(plugin_list, plugin_start, NULL);
}

/**
 * l_plugin_unload:
 *
 * Unload all plugins.
 **/
LIB_EXPORT void l_plugin_unload(void)
{
	if (!plugin_list)
		return;

	l_queue_reverse(plugin_list);

	l_queue_destroy(plugin_list, plugin_destroy);

	plugin_list = NULL;
}
