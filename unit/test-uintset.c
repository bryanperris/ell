/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
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

#include <assert.h>

#include <ell/ell.h>

static void test_uintset(const void *data)
{
	struct l_uintset *set;
	int i;
	bool r;

	set = l_uintset_new_from_range(1, 76);
	assert(set);

	assert(l_uintset_get_min(set) == 1);
	assert(l_uintset_get_max(set) == 76);

	assert(l_uintset_find_min(set) == 77);
	assert(l_uintset_find_max(set) == 77);
	assert(l_uintset_find_unused_min(set) == 1);

	r = l_uintset_put(set, 78);
	assert(!r);

	r = l_uintset_contains(set, 1);
	assert(!r);

	r = l_uintset_put(set, 1);
	assert(r);

	r = l_uintset_contains(set, 1);
	assert(r);

	r = l_uintset_take(set, 78);
	assert(!r);

	r = l_uintset_take(set, 1);
	assert(r);

	r = l_uintset_contains(set, 1);
	assert(!r);

	assert(l_uintset_put(set, 2));
	assert(l_uintset_put(set, 75));

	assert(l_uintset_find_min(set) == 2);
	assert(l_uintset_find_max(set) == 75);

	for (i = 1; i <= 76; i++)
		assert(l_uintset_put(set, i));

	assert(l_uintset_find_unused_min(set) == 77);

	assert(l_uintset_take(set, 76));
	assert(l_uintset_find_unused_min(set) == 76);

	l_uintset_free(set);
}

static void test_uintset_2(const void *data)
{
	struct l_uintset *set;

	set = l_uintset_new_from_range(0, 63);
	assert(set);

	assert(l_uintset_find_min(set) == 64);
	assert(l_uintset_find_max(set) == 64);

	assert(l_uintset_put(set, 63));
	assert(l_uintset_find_min(set) == 63);
	assert(l_uintset_find_max(set) == 63);

	l_uintset_free(set);
}

static void test_uintset_3(const void *data)
{
	struct l_uintset *set;

	set = l_uintset_new_from_range(0, 62);
	assert(set);

	assert(l_uintset_find_min(set) == 63);
	assert(l_uintset_find_max(set) == 63);
	assert(l_uintset_put(set, 62));
	assert(l_uintset_find_min(set) == 62);
	assert(l_uintset_find_max(set) == 62);

	l_uintset_free(set);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("l_uintset sanity check", test_uintset, NULL);
	l_test_add("l_uintset sanity check #2", test_uintset_2, NULL);
	l_test_add("l_uintset sanity check #3", test_uintset_3, NULL);

	return l_test_run();
}
