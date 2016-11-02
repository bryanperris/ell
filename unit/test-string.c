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

	a = l_string_unwrap(str);
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

	a = l_string_unwrap(str);
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

	a = l_string_unwrap(str);
	assert(a);
	assert(!strcmp(a, test->expected));

	l_free(a);
}

static void test_truncate(const void *test_data)
{
	struct l_string *str;
	char *a;

	str = l_string_new(7);
	l_string_append(str, "Foobar7");

	assert(!l_string_truncate(NULL, 8));

	assert(l_string_truncate(str, 7));
	a = l_string_unwrap(str);
	assert(a);
	assert(!strcmp(a, "Foobar7"));
	l_free(a);

	str = l_string_new(7);
	l_string_append(str, "Foobar7");
	assert(l_string_truncate(str, 3));
	l_string_append_c(str, '4');
	a = l_string_unwrap(str);
	assert(a);
	assert(!strcmp(a, "Foo4"));
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

	strv = l_strsplit(":bar:::bz", ':');
	assert(strv);
	assert(!strcmp(strv[0], ""));
	assert(!strcmp(strv[1], "bar"));
	assert(!strcmp(strv[2], ""));
	assert(!strcmp(strv[3], ""));
	assert(!strcmp(strv[4], "bz"));
	assert(strv[5] == NULL);
	l_strfreev(strv);

	strv = l_strsplit("Foo:bar:", ':');
	assert(strv);
	assert(!strcmp(strv[0], "Foo"));
	assert(!strcmp(strv[1], "bar"));
	assert(!strcmp(strv[2], ""));
	assert(strv[3] == NULL);
	l_strfreev(strv);
}

static void test_strsplit_set(const void *test_data)
{
	char **strv = l_strsplit_set("Foo:bar,Baz Blu", ":, ");

	assert(strv);
	assert(!strcmp(strv[0], "Foo"));
	assert(!strcmp(strv[1], "bar"));
	assert(!strcmp(strv[2], "Baz"));
	assert(!strcmp(strv[3], "Blu"));
	assert(strv[4] == NULL);
	l_strfreev(strv);

	strv = l_strsplit_set("Foo:bar,Baz Blu,:,Fee:Fie ", ":, ");
	assert(strv);
	assert(!strcmp(strv[0], "Foo"));
	assert(!strcmp(strv[1], "bar"));
	assert(!strcmp(strv[2], "Baz"));
	assert(!strcmp(strv[3], "Blu"));
	assert(!strcmp(strv[4], ""));
	assert(!strcmp(strv[5], ""));
	assert(!strcmp(strv[6], "Fee"));
	assert(!strcmp(strv[7], "Fie"));
	assert(!strcmp(strv[8], ""));
	assert(strv[9] == NULL);
	l_strfreev(strv);
}

static void test_joinv(const void *test_data)
{
	char *strv1[] = { NULL };
	char *strv2[] = { "Foo", "Bar", NULL };
	char **strv3 = l_strsplit("Foo:bar:bz", ':');
	char *r;

	assert(!l_strjoinv(NULL, ':'));

	r = l_strjoinv(strv1, ':');
	assert(r);
	assert(!strcmp(r, ""));
	l_free(r);

	r = l_strjoinv(strv2, ':');
	assert(r);
	assert(!strcmp(r, "Foo:Bar"));
	l_free(r);

	r = l_strjoinv(strv3, ':');
	assert(r);
	assert(!strcmp(r, "Foo:bar:bz"));
	l_free(r);

	l_strfreev(strv3);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("Grow Test", test_grow, NULL);
	l_test_add("printf Test", test_printf, NULL);

	l_test_add("append_fixed test 1", test_fixed, &fixed_test1);
	l_test_add("append_fixed test 2", test_fixed, &fixed_test2);
	l_test_add("append_fixed test 3", test_fixed, &fixed_test3);

	l_test_add("truncate", test_truncate, NULL);

	l_test_add("strsplit", test_strsplit, NULL);
	l_test_add("strsplit_set", test_strsplit_set, NULL);

	l_test_add("joinv", test_joinv, NULL);

	return l_test_run();
}
