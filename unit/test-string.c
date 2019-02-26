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

static void test_strv_length(const void *test_data)
{
	char *strv1[] = { NULL };
	char *strv2[] = { "Foo", "Bar", NULL };

	assert(l_strv_length(NULL) == 0);
	assert(l_strv_length(strv1) == 0);
	assert(l_strv_length(strv2) == 2);
}

static void test_strv_contains(const void *test_data)
{
	char *strv1[] = { NULL };
	char *strv2[] = { "Foo", "Bar", NULL };
	char *strv3[] = { "Foo", "Bar", "", NULL };

	assert(l_strv_contains(NULL, "Foo") == false);
	assert(l_strv_contains(strv2, NULL) == false);
	assert(l_strv_contains(NULL, NULL) == false);
	assert(l_strv_contains(strv1, "Baz") == false);
	assert(l_strv_contains(strv1, "") == false);
	assert(l_strv_contains(strv2, "Baz") == false);
	assert(l_strv_contains(strv2, "") == false);
	assert(l_strv_contains(strv2, "Bar") == true);
	assert(l_strv_contains(strv3, "Baz") == false);
	assert(l_strv_contains(strv3, "") == true);
	assert(l_strv_contains(strv3, "Bar") == true);
}

static void test_strv_append(const void *test_data)
{
	const char *src[] = { "Foo", "Bar" };
	char **dst = NULL;
	size_t len = L_ARRAY_SIZE(src);
	size_t i;

	for (i = 0; i < len; i++)
		dst = l_strv_append(dst, src[i]);

	assert(l_strv_length(dst) == len);

	for (i = 0; i < len; i++)
		assert(strcmp(src[i], dst[i]) == 0);

        l_strv_free(dst);
}

static void test_parse_args(const void *test_data)
{
	static struct test_case {
		bool retval;
		const char *args;
		int n_args;
		const char *result[10];
	} tests[] = {
	{ true, "one", 1, { "one" } },
	{ true, "one two", 2, { "one", "two" } },
	{ true, "one two three ", 3, { "one", "two", "three" } },
	{ true, " \tfoo\t\tbar ", 2, { "foo", "bar" } },
	{ true, "red , white blue", 4, { "red", ",", "white", "blue" } },
	{ true, "one \"two three\"", 2, { "one", "two three" } },
	{ true, "\"quoted\"", 1, { "quoted" } },
	{ true, "'singly-quoted'", 1, { "singly-quoted" } },
	{ true, "contin\\\nuation", 1, { "continuation" } },
	{ true, "explicit ''", 2, { "explicit", "" } },
	{ true, "explicit \"\"", 2, { "explicit", "" } },
	{ true, "", 0, { } },
	{ false, "new\nline", 0, { } },
	};

	unsigned int i;

	for (i = 0; i < L_ARRAY_SIZE(tests); i++) {
		int j;
		int n_args;
		char **args = l_parse_args(tests[i].args, &n_args);

		if (!tests[i].retval) {
			assert(!args);
			continue;
		}

		assert(args);
		assert(n_args == tests[i].n_args);

		for (j = 0; j < n_args; j++)
			assert(!strcmp(args[j], tests[i].result[j]));

		assert(!args[j]);
		l_strfreev(args);
	}
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

	l_test_add("strv_length", test_strv_length, NULL);
	l_test_add("strv_contains", test_strv_contains, NULL);
	l_test_add("strv_append", test_strv_append, NULL);

	l_test_add("parse_args", test_parse_args, NULL);

	return l_test_run();
}
