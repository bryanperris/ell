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
#include <stdio.h>
#include <limits.h>

#include <ell/ell.h>

struct settings_test {
	const char *input;
};

static struct settings_test settings_test1 = {
	.input = "[Foobar]\n#Comment\n#Comment2\nKey=Value\n"
		"IntegerA=2147483647\nIntegerB=-2147483648\n"
		"IntegerC=4294967295\nIntegerD=9223372036854775807\n"
		"IntegerE=-9223372036854775808\n"
		"IntegerF=18446744073709551615\n"
		"IntegerG=2247483647\nIntegerH=4294967296\n"
		"IntegerI=9223372036854775808\n"
		"IntegerJ=18446744073709551616\n"
		"String=\\tFoobar\\s\n"
		"StringBad1=Foobar\\\n"
		"StringBad2=Foobar\\b123\n",
};

static void settings_debug(const char *str, void *userdata)
{
	printf("%s\n", str);
}

static void test_settings(const void *test_data)
{
	const struct settings_test *test = test_data;
	struct l_settings *settings;
	int int32;
	unsigned int uint32;
	int64_t int64;
	uint64_t uint64;
	char *str;

	settings = l_settings_new();

	l_settings_set_debug(settings, settings_debug, NULL, NULL);

	l_settings_load_from_data(settings, test->input, strlen(test->input));

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

	str = l_settings_get_string(settings, "Foobar", "StringBad1");
	assert(!str);

	str = l_settings_get_string(settings, "Foobar", "StringBad2");
	assert(!str);

	l_settings_free(settings);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("Settings Test 1", test_settings, &settings_test1);

	return l_test_run();
}
