/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2015-2019  Intel Corporation. All rights reserved.
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
#include <limits.h>

#include <ell/ell.h>

static void test_uintset(const void *data)
{
	struct l_uintset *set;
	int i;
	bool r;

	assert(l_uintset_get_min(NULL) == UINT_MAX);
	assert(l_uintset_find_max(NULL) == UINT_MAX);
	assert(l_uintset_find_min(NULL) == UINT_MAX);

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

static void test_uintset_4(const void *data)
{
	assert(!l_uintset_take(NULL, 1));
	assert(!l_uintset_put(NULL, 1));
	assert(!l_uintset_contains(NULL, 1));
}

static void test_uintset_find_unused(const void *data)
{
	struct l_uintset *set;
	int i;

	set = l_uintset_new_from_range(0, 63);
	assert(set);

	assert(l_uintset_put(set, 0));
	assert(l_uintset_find_unused_min(set) == 1);
	assert(l_uintset_put(set, 1));
	assert(l_uintset_find_unused_min(set) == 2);

	for (i = 0; i < 64; i++)
		assert(l_uintset_put(set, i));

	assert(l_uintset_find_unused_min(set) == 64);

	assert(l_uintset_take(set, 60));
	assert(l_uintset_find_unused_min(set) == 60);
	assert(l_uintset_find_unused(set, 55) == 60);
	assert(l_uintset_find_unused(set, 60) == 60);
	assert(l_uintset_find_unused(set, 61) == 60);
	l_uintset_free(set);

	set = l_uintset_new_from_range(15, 72);
	assert(set);

	for (i = 15; i < 64; i++)
		assert(l_uintset_put(set, i));

	assert(l_uintset_find_unused_min(set) == 64);
	assert(l_uintset_find_unused(set, 55) == 64);
	assert(l_uintset_find_unused(set, 70) == 70);
	assert(l_uintset_put(set, 70));
	assert(l_uintset_find_unused(set, 70) == 71);

	l_uintset_free(set);
}

static void uintset_foreach(uint32_t number, void *user_data)
{
	struct l_uintset *check = user_data;

	l_uintset_take(check, number);
}

static void test_uintset_foreach(const void *data)
{
	struct l_uintset *set;
	struct l_uintset *check;
	int i;

	set = l_uintset_new_from_range(0, 63);
	check = l_uintset_new_from_range(0, 63);
	assert(set);
	assert(check);

	for (i = 0; i < 64; i++) {
		assert(l_uintset_put(set, i));
		assert(l_uintset_put(check, i));
	}

	l_uintset_foreach(set, uintset_foreach, check);
	assert(l_uintset_find_max(check) == 64);

	l_uintset_free(set);
	l_uintset_free(check);

	set = l_uintset_new_from_range(0, 127);
	check = l_uintset_new_from_range(0, 127);
	assert(set);
	assert(check);

	assert(l_uintset_put(set, 127));
	assert(l_uintset_put(check, 127));

	l_uintset_foreach(set, uintset_foreach, check);
	assert(l_uintset_find_max(check) == 128);

	l_uintset_free(set);
	l_uintset_free(check);

	set = l_uintset_new_from_range(0, 191);
	check = l_uintset_new_from_range(0, 191);
	assert(set);
	assert(check);

	assert(l_uintset_put(set, 50));
	assert(l_uintset_put(check, 50));
	assert(l_uintset_put(set, 150));
	assert(l_uintset_put(check, 150));

	l_uintset_foreach(set, uintset_foreach, check);
	assert(l_uintset_find_max(check) == 192);

	l_uintset_free(set);
	l_uintset_free(check);

	set = l_uintset_new_from_range(0, 192);
	check = l_uintset_new_from_range(0, 192);
	assert(set);
	assert(check);

	assert(l_uintset_put(set, 0));
	assert(l_uintset_put(check, 0));
	assert(l_uintset_put(set, 63));
	assert(l_uintset_put(check, 63));
	assert(l_uintset_put(set, 120));
	assert(l_uintset_put(check, 120));

	l_uintset_foreach(set, uintset_foreach, check);
	assert(l_uintset_find_max(check) == 193);

	l_uintset_free(set);
	l_uintset_free(check);

	set = l_uintset_new_from_range(0, 192);
	check = l_uintset_new_from_range(0, 192);
	assert(set);
	assert(check);

	assert(l_uintset_put(set, 0));
	assert(l_uintset_put(check, 0));

	assert(l_uintset_put(set, 192));
	assert(l_uintset_put(check, 192));

	l_uintset_foreach(set, uintset_foreach, check);
	assert(l_uintset_find_max(check) == 193);

	l_uintset_free(set);
	l_uintset_free(check);
}

static void test_uintset_intersect_sanity_test(const void *data)
{
	struct l_uintset *set_a;
	struct l_uintset *set_b;

	assert(!l_uintset_intersect(NULL, NULL));

	set_a = l_uintset_new_from_range(0, 5);
	assert(!l_uintset_intersect(NULL, set_a));
	assert(!l_uintset_intersect(set_a, NULL));

	set_b = l_uintset_new_from_range(4, 10);
	assert(!l_uintset_intersect(set_a, set_b));

	l_uintset_free(set_a);
	l_uintset_free(set_b);
}

struct uintset_data {
	const uint32_t min;
	const uint32_t max;
	const uint32_t *vals;
	const uint32_t size;
};

struct uintset_intersect_data {
	const struct uintset_data set_a;
	const struct uintset_data set_b;
	const struct uintset_data set_r;
};

static const uint32_t vals1[] = { 1, 2, 3 };
static const uint32_t vals2[] = { 3, 4};
static const uint32_t vals3[] = { 3 };

static const struct uintset_intersect_data intersect_data_1 = {
	.set_a = { 0, 4, vals1, L_ARRAY_SIZE(vals1) },
	.set_b = { 0, 4, vals2, L_ARRAY_SIZE(vals2) },
	.set_r = { 0, 4, vals3, L_ARRAY_SIZE(vals3) },
};

static const uint32_t vals4[] = { 0, 1, 64, 127 };
static const uint32_t vals5[] = { 1, 25, 64, 66, 127, 135 };
static const uint32_t vals6[] = { 1, 64, 127 };

static const struct uintset_intersect_data intersect_data_2 = {
	.set_a = { 0, 191, vals4, L_ARRAY_SIZE(vals4) },
	.set_b = { 0, 191, vals5, L_ARRAY_SIZE(vals5) },
	.set_r = { 0, 191, vals6, L_ARRAY_SIZE(vals6) },
};

static void test_uintset_intersect_test(const void *user_data)
{
	const struct uintset_intersect_data *data = user_data;
	struct l_uintset *set_a;
	struct l_uintset *set_b;
	struct l_uintset *set_r;
	size_t i;

	set_a = l_uintset_new_from_range(data->set_a.min, data->set_a.max);

	for (i = 0; i < data->set_a.size; i++)
		l_uintset_put(set_a, data->set_a.vals[i]);

	set_b = l_uintset_new_from_range(data->set_b.min, data->set_b.max);

	for (i = 0; i < data->set_b.size; i++)
		l_uintset_put(set_b, data->set_b.vals[i]);

	set_r = l_uintset_intersect(set_a, set_b);

	assert(set_r);

	for (i = 0; i < data->set_r.size; i++) {
		assert(l_uintset_contains(set_r, data->set_r.vals[i]));
		assert(l_uintset_take(set_r, data->set_r.vals[i]));
	}

	assert(l_uintset_find_max(set_r) == l_uintset_get_max(set_r) + 1);

	l_uintset_free(set_a);
	l_uintset_free(set_b);
	l_uintset_free(set_r);
}

static void test_uintset_isempty(const void *user_data)
{
	struct l_uintset *a = NULL;
	struct l_uintset *b = l_uintset_new(32);
	struct l_uintset *c = l_uintset_new(32);

	assert(l_uintset_put(c, 10));

	assert(l_uintset_isempty(a));
	assert(l_uintset_isempty(b));
	assert(!l_uintset_isempty(c));

	l_uintset_free(c);
	l_uintset_free(b);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("l_uintset sanity check", test_uintset, NULL);
	l_test_add("l_uintset sanity check #2", test_uintset_2, NULL);
	l_test_add("l_uintset sanity check #3", test_uintset_3, NULL);
	l_test_add("l_uintset sanity check #4", test_uintset_4, NULL);
	l_test_add("l_uintset for each tests", test_uintset_foreach, NULL);
	l_test_add("l_uintset find unused tests", test_uintset_find_unused,
							NULL);
	l_test_add("l_uintset intersect sanity check",
			test_uintset_intersect_sanity_test, NULL);
	l_test_add("l_uintset intersect test 1", test_uintset_intersect_test,
							&intersect_data_1);
	l_test_add("l_uintset intersect test 2", test_uintset_intersect_test,
							&intersect_data_2);
	l_test_add("l_uintset isempty", test_uintset_isempty, NULL);

	return l_test_run();
}
