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
#include <stdio.h>
#include <limits.h>

#include <ell/ell.h>

static const char *data1 = "[Foobar]\n#Comment\n#Comment2\nKey=Value\n"
		"IntegerA=2147483647\nIntegerB=-2147483648\n"
		"IntegerC=4294967295\nIntegerD=9223372036854775807\n"
		"IntegerE=-9223372036854775808\n"
		"IntegerF=18446744073709551615\n"
		"IntegerG=2247483647\nIntegerH=4294967296\n"
		"IntegerI=9223372036854775808\n"
		"IntegerJ=18446744073709551616\n"
		"String=\\tFoobar\\s\n"
		"StringEmpty=\n"
		"StringBad1=Foobar\\\n"
		"StringBad2=Foobar\\b123\n"
		"StringList=Foo,Bar,Baz\n"
		"StringListEmpty=\n"
		"StringListOne=FooBarBaz\n";

static const char *data2 = "[Group1]\nKey=Value\n"
			"IntegerA=2147483647\nIntegerB=-2147483648\n"
			"IntegerC=4294967295\nIntegerD=9223372036854775807\n"
			"IntegerE=-9223372036854775808\n"
			"IntegerF=18446744073709551615\n"
			"IntegerG=2247483647\nIntegerH=4294967296\n"
			"String=\\tFoobar\\s\n"
			"StringEmpty=\n"
			"StringBad1=Foobar\\\n"
			"StringBad2=Foobar\\b123\n"
			"StringList=Foo,Bar,Baz\n"
			"StringListEmpty=\n"
			"StringListOne=FooBarBaz\n\n"
			"[Group2]\nKey=Value\n";

static void settings_debug(const char *str, void *userdata)
{
	printf("%s\n", str);
}

static void test_settings(struct l_settings *settings)
{
	int int32;
	unsigned int uint32;
	int64_t int64;
	uint64_t uint64;
	char *str;
	char **strv;

	assert(l_settings_has_group(settings, "Foobar"));
	assert(!l_settings_has_group(settings, "Foobar2"));

	assert(l_settings_has_key(settings, "Foobar", "Key"));
	assert(!l_settings_has_key(settings, "Foobar", "Key2"));

	assert(!l_settings_get_bool(settings, "Foobar", "Key", NULL));

	assert(l_settings_get_int(settings, "Foobar", "IntegerA", &int32));
	assert(l_settings_get_int(settings, "Foobar", "IntegerB", &int32));
	assert(l_settings_get_uint(settings, "Foobar", "IntegerC", &uint32));
	assert(l_settings_get_int64(settings, "Foobar", "IntegerD", &int64));
	assert(l_settings_get_int64(settings, "Foobar", "IntegerE", &int64));
	assert(l_settings_get_uint64(settings, "Foobar", "IntegerF", &uint64));
	assert(!l_settings_get_int(settings, "Foobar", "IntegerG", &int32));
	assert(!l_settings_get_uint(settings, "Foobar", "FoobarH", &uint32));
	assert(!l_settings_get_int64(settings, "Foobar", "IntegerI", &int64));
	assert(!l_settings_get_uint64(settings, "Foobar", "IntegerJ", &uint64));

	str = l_settings_get_string(settings, "Foobar", "String");
	assert(str);
	assert(!strcmp(str, "\tFoobar "));
	l_free(str);

	str = l_settings_get_string(settings, "Foobar", "StringEmpty");
	assert(str);
	assert(!strcmp(str, ""));
	l_free(str);

	str = l_settings_get_string(settings, "Foobar", "StringBad1");
	assert(!str);

	str = l_settings_get_string(settings, "Foobar", "StringBad2");
	assert(!str);

	strv = l_settings_get_string_list(settings, "Foobar",
						"StringList", ',');
	assert(strv);
	assert(!strcmp(strv[0], "Foo"));
	assert(!strcmp(strv[1], "Bar"));
	assert(!strcmp(strv[2], "Baz"));
	assert(strv[3] == NULL);
	l_strfreev(strv);

	strv = l_settings_get_string_list(settings, "Foobar", "StringListEmpty",						',');
	assert(strv);
	assert(strv[0] == NULL);
	l_strfreev(strv);

	strv = l_settings_get_string_list(settings, "Foobar", "StringListOne",
						',');
	assert(strv);
	assert(strv[0]);
	assert(!strcmp(strv[0], "FooBarBaz"));
	assert(strv[1] == NULL);
	l_strfreev(strv);

	strv = l_settings_get_groups(settings);
	assert(strv);
	assert(!strcmp(strv[0], "Foobar"));
	assert(!strv[1]);
	l_strfreev(strv);

	assert(!l_settings_get_keys(settings, "Nonexistent"));

	strv = l_settings_get_keys(settings, "Foobar");
	assert(strv);
	l_strfreev(strv);

	assert(!l_settings_remove_key(settings, "Bar", "Foo"));
	assert(!l_settings_remove_key(settings, "Foobar", "Nonexistent"));
	assert(l_settings_remove_key(settings, "Foobar", "Key"));
	assert(!l_settings_has_key(settings, "Foobar", "Key"));

	assert(!l_settings_remove_group(settings, "Bar"));
	assert(l_settings_remove_group(settings, "Foobar"));
	assert(!l_settings_has_group(settings, "Foobar"));
}

static void test_load_from_data(const void *test_data)
{
	struct l_settings *settings;

	settings = l_settings_new();

	l_settings_set_debug(settings, settings_debug, NULL, NULL);
	l_settings_load_from_data(settings, data1, strlen(data1));

	test_settings(settings);

	l_settings_free(settings);
}

static void test_load_from_file(const void *test_data)
{
	struct l_settings *settings;

	settings = l_settings_new();

	l_settings_set_debug(settings, settings_debug, NULL, NULL);
	assert(l_settings_load_from_file(settings, UNITDIR "settings.test"));

	test_settings(settings);

	l_settings_free(settings);
}

static void test_set_methods(const void *test_data)
{
	struct l_settings *settings;
	int int32;
	unsigned int uint32;
	int64_t int64;
	uint64_t uint64;
	bool b;
	const char *v;
	char *s;

	settings = l_settings_new();

	l_settings_set_debug(settings, settings_debug, NULL, NULL);

	/* Integer tests */
	assert(l_settings_set_int(settings, "Main", "Integers", -15));
	assert(l_settings_get_int(settings, "Main", "Integers", &int32));
	assert(int32 == -15);
	v = l_settings_get_value(settings, "Main", "Integers");
	assert(v);
	assert(!strcmp(v, "-15"));

	assert(l_settings_set_uint(settings, "Main", "Integers", 15));
	assert(l_settings_get_uint(settings, "Main", "Integers", &uint32));
	assert(uint32 == 15);
	v = l_settings_get_value(settings, "Main", "Integers");
	assert(v);
	assert(!strcmp(v, "15"));

	assert(l_settings_set_int64(settings, "Main", "Integers", -2423492340ll));
	assert(l_settings_get_int64(settings, "Main", "Integers", &int64));
	assert(int64 == -2423492340ll);
	v = l_settings_get_value(settings, "Main", "Integers");
	assert(v);
	assert(!strcmp(v, "-2423492340"));

	assert(l_settings_set_uint64(settings, "Main", "Integers", 2423492340ul));
	assert(l_settings_get_uint64(settings, "Main", "Integers", &uint64));
	assert(uint64 == 2423492340ul);
	v = l_settings_get_value(settings, "Main", "Integers");
	assert(v);
	assert(!strcmp(v, "2423492340"));

	/* Boolean tests */
	assert(l_settings_set_bool(settings, "Main", "Boolean", true));
	assert(l_settings_get_bool(settings, "Main", "Boolean", &b));
	assert(b == true);
	v = l_settings_get_value(settings, "Main", "Boolean");
	assert(v);
	assert(!strcmp(v, "true"));

	assert(l_settings_set_bool(settings, "Main", "Boolean", false));
	assert(l_settings_get_bool(settings, "Main", "Boolean", &b));
	assert(b == false);
	v = l_settings_get_value(settings, "Main", "Boolean");
	assert(v);
	assert(!strcmp(v, "false"));

	/* String tests */
	assert(l_settings_set_string(settings, "Main", "String", "  \tFoobar"));
	s = l_settings_get_string(settings, "Main", "String");
	assert(s);
	assert(!strcmp(s, "  \tFoobar"));
	l_free(s);
	v = l_settings_get_value(settings, "Main", "String");
	assert(v);
	assert(!strcmp(v, "\\s\\s\\tFoobar"));

	assert(l_settings_set_string(settings, "Main", "Escapes",
					" \\Text\t\n\r\\"));
	s = l_settings_get_string(settings, "Main", "Escapes");
	assert(s);
	assert(!strcmp(s, " \\Text\t\n\r\\"));
	l_free(s);
	v = l_settings_get_value(settings, "Main", "Escapes");
	assert(v);
	assert(!strcmp(v, "\\s\\\\Text\t\\n\\r\\\\"));

	l_settings_free(settings);
}

static void test_to_data(const void *test_data)
{
	const char *data = test_data;
	struct l_settings *settings;
	char *res;
	size_t res_len;

	settings = l_settings_new();

	l_settings_set_debug(settings, settings_debug, NULL, NULL);
	l_settings_load_from_data(settings, data2, strlen(data2));

	res = l_settings_to_data(settings, &res_len);

	assert(!strcmp(res, data));
	l_free(res);

	l_settings_free(settings);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("Load from Data", test_load_from_data, NULL);
	l_test_add("Load from File", test_load_from_file, NULL);
	l_test_add("Set Methods", test_set_methods, NULL);
	l_test_add("Export to Data 1", test_to_data, data2);

	return l_test_run();
}
