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
	assert(l_string_length(str) == strlen("Foobar7BarFoo"));

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

	assert(l_string_length(str) == strlen("Foobar7100BarFoo"));

	a = l_string_free(str, false);
	assert(a);
	assert(!strcmp(a, "Foobar7100BarFoo"));

	l_free(a);
}

static const char fixed1[] = { 'a', 'b', 'c', 'd', '\0', 'e', 'f', 'g' };
static const char fixed2[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', '\0' };
static const char fixed3[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' };

struct fixed_test {
	const char *input;
	unsigned int input_len;
	const char *expected;
};

static struct fixed_test fixed_test1 = {
	.input = fixed1,
	.input_len = sizeof(fixed1),
	.expected = "Foobar7abcd"
};

static struct fixed_test fixed_test2 = {
	.input = fixed2,
	.input_len = sizeof(fixed2),
	.expected = "Foobar7abcdefg"
};

static struct fixed_test fixed_test3 = {
	.input = fixed3,
	.input_len = sizeof(fixed3),
	.expected = "Foobar7abcdefgh"
};

static void test_fixed(const void *test_data)
{
	const struct fixed_test *test = test_data;
	struct l_string *str;
	char *a;

	str = l_string_new(7);
	l_string_append(str, "Foobar7");

	l_string_append_fixed(str, test->input, test->input_len);
	assert(l_string_length(str) == strlen(test->expected));

	a = l_string_free(str, false);
	assert(a);
	assert(!strcmp(a, test->expected));

	l_free(a);
}

static void test_strsplit(const void *test_data)
{
	char **strv = l_strsplit("Foo:bar:bz", ':');

	assert(strv);
	assert(!strcmp(strv[0], "Foo"));
	assert(!strcmp(strv[1], "bar"));
	assert(!strcmp(strv[2], "bz"));
	assert(strv[3] == NULL);
	l_strfreev(strv);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("Grow Test", test_grow, NULL);
	l_test_add("printf Test", test_printf, NULL);

	l_test_add("append_fixed test 1", test_fixed, &fixed_test1);
	l_test_add("append_fixed test 2", test_fixed, &fixed_test2);
	l_test_add("append_fixed test 3", test_fixed, &fixed_test3);

	l_test_add("strplit", test_strsplit, NULL);

	return l_test_run();
}
