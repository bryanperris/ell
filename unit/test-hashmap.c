/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2012  Intel Corporation. All rights reserved.
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
	struct l_hashmap *hashmap;
	unsigned int n, i;

	hashmap = l_hashmap_new();
	if (!hashmap)
		return 1;

	for (n = 0; n < 1024; n++) {
		for (i = 1; i < n + 2; i++) {
			if (!l_hashmap_insert(hashmap, L_UINT_TO_PTR(i),
							L_UINT_TO_PTR(i)))
				printf("[%u] insert error: %u\n", n, i);
		}

		if (l_hashmap_size(hashmap) != n + 1) {
			printf("[%u] size mismatch: %u\n", n,
						l_hashmap_size(hashmap));
		}

		for (i = 1; i < n + 2; i++) {
			void *ptr = l_hashmap_lookup(hashmap, L_UINT_TO_PTR(i));

			if (!ptr) {
				printf("[%u] lookup empty: %u\n", n, i);
				continue;
			}

			if (i != L_PTR_TO_UINT(ptr)) {
				printf("[%u] lookup misatch: %u != %u\n",
						n, i, L_PTR_TO_UINT(ptr));
			}
		}

		for (i = 1; i < n + 2; i++) {
			void *ptr = l_hashmap_remove(hashmap, L_UINT_TO_PTR(i));

			if (!ptr) {
				printf("[%u] remove empty: %u\n", n, i);
				continue;
			}

			if (i != L_PTR_TO_UINT(ptr)) {
				printf("[%u] remove misatch: %u != %u\n",
						n, i, L_PTR_TO_UINT(ptr));
			}
		}

		if (!l_hashmap_isempty(hashmap)) {
			printf("[%u] not empty: %u\n", n,
						l_hashmap_size(hashmap));
		}
	}

	l_hashmap_destroy(hashmap, NULL);

	return 0;
}
