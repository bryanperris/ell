/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2019 Intel Corporation. All rights reserved.
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

static void test_before_after_diff(const void *data)
{
	uint64_t small = 10;
	uint64_t big = 100;

	assert(l_time_after(big, small));
	assert(l_time_before(small, big));
	assert(l_time_diff(small, big) == l_time_diff(big, small));
}

static void test_offset(const void *data)
{
	uint64_t max = UINT64_MAX;
	uint64_t max_minus = UINT64_MAX - 1000;

	assert(l_time_offset(max, 1) == UINT64_MAX);
	assert(l_time_offset(max, max) == UINT64_MAX);
	assert(l_time_offset(max_minus, 1000) == max);
	assert(l_time_offset(max_minus, 1001) == UINT64_MAX);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("Test before/after/diff", test_before_after_diff, NULL);
	l_test_add("Test offset", test_offset, NULL);

	return l_test_run();
}
