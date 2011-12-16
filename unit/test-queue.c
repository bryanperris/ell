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

#include <ell/ell.h>

int main(int argc, char *argv[])
{
	struct l_queue *queue;
	unsigned int n, i;

	queue = l_queue_new();
	if (!queue)
		return 1;

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

	return 0;
}
