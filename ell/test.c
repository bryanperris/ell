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

#include <stdio.h>

#include "util.h"
#include "queue.h"
#include "test.h"
#include "private.h"

/**
 * SECTION:test
 * @short_description: Unit test framework
 *
 * Unit test framework
 */

struct entry {
	const char *name;
	l_test_func_t function;
	const void *test_data;
};

static struct l_queue *queue;

/**
 * l_test_init:
 * @argc: pointer to @argc parameter of main() function
 * @argv: pointer to @argv parameter of main() function
 *
 * Initialize testing framework.
 **/
LIB_EXPORT void l_test_init(int *argc, char ***argv)
{
	queue = l_queue_new();
}

/**
 * l_test_run:
 *
 * Run all configured tests.
 *
 * Returns: 0 on success
 **/
LIB_EXPORT int l_test_run(void)
{
	for (;;) {
		struct entry *entry;

		entry = l_queue_pop_head(queue);
		if (!entry)
			break;

		printf("TEST: %s\n", entry->name);

		entry->function(entry->test_data);

		l_free(entry);
	}

	return 0;
}

/**
 * l_test_add:
 * @name: test name
 * @function: test function
 * @test_data: test data
 *
 * Add new test.
 **/
LIB_EXPORT void l_test_add(const char *name, l_test_func_t function,
						const void *test_data)
{
	struct entry *entry;

	if (!name || !function)
		return;

	entry = l_new(struct entry, 1);

	entry->name = name;
	entry->function = function;
	entry->test_data = test_data;

	if (!l_queue_push_tail(queue, entry))
		l_free(queue);
}
