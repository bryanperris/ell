/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2014  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <assert.h>

#include <ell/ell.h>

static void test_push_pop(const void *data)
{
	struct l_queue *queue;
	unsigned int n, i;

	queue = l_queue_new();
	assert(queue);

	for (n = 0; n < 1024; n++) {
		for (i = 1; i < n + 2; i++) {
			l_queue_push_tail(queue, L_UINT_TO_PTR(i));
		}

		if (l_queue_length(queue) != n + 1) {
			printf("[%u] length mismatch: %u\n", n,
						l_queue_length(queue));
		}

		for (i = 1; i < n + 2; i++) {
			void *ptr = l_queue_pop_head(queue);

			if (!ptr) {
				printf("[%u] entry empty: %u\n", n, i);
				continue;
			}

			if (i != L_PTR_TO_UINT(ptr)) {
				printf("[%u] entry misatch: %u != %u\n",
						n, i, L_PTR_TO_UINT(ptr));
			}
		}

		if (!l_queue_isempty(queue)) {
			printf("[%u] not empty: %u\n", n,
						l_queue_length(queue));
		}
	}

	l_queue_destroy(queue, NULL);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("queue push & pop", test_push_pop, NULL);

	return l_test_run();
}
