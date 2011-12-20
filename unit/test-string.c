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

#include <assert.h>

#include <ell/ell.h>

static void test_grow(const void *test_data)
{
	struct l_string *str;
	char *a;

	str = l_string_new(7);
	assert(str);

	assert(l_string_append(str, "Foobar7") == str);
	assert(l_string_append(str, "BarFoo"));

	a = l_string_free(str, false);
	assert(a);
	assert(!strcmp(a, "Foobar7BarFoo"));

	l_free(a);
}

static void test_printf(const void *test_data)
{
	struct l_string *str;
	char *a;

	str = l_string_new(7);
	l_string_append(str, "Foobar7");

	l_string_append_printf(str, "%d", 100);
	l_string_append_printf(str, "%s", "BarFoo");

	a = l_string_free(str, false);
	assert(a);
	assert(!strcmp(a, "Foobar7100BarFoo"));

	l_free(a);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("Grow Test", test_grow, NULL);
	l_test_add("printf Test", test_printf, NULL);

	return l_test_run();
}
