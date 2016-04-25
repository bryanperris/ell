/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2015  Intel Corporation. All rights reserved.
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

static void test_hexstring(const void *test_data)
{
	unsigned char test[] = { 0x74, 0x65, 0x73, 0x74, 0x00 };
	char *hex;

	hex = l_util_hexstring(test, 5);
	assert(hex);
	assert(!strcmp(hex, "7465737400"));
	l_free(hex);
}

static void test_from_hexstring(const void *test_data)
{
	const char *test = "7465737400";
	unsigned char expected[] = { 0x74, 0x65, 0x73, 0x74, 0x00 };
	const char *invalid1 = "74757";
	const char *invalid2 = "746573740";

	unsigned char *bytes;
	size_t len;

	bytes = l_util_from_hexstring(test, &len);
	assert(bytes);
	assert(len == 5);
	assert(!memcmp(bytes, expected, len));
	l_free(bytes);

	bytes = l_util_from_hexstring(invalid1, &len);
	assert(!bytes);

	bytes = l_util_from_hexstring(invalid2, &len);
	assert(!bytes);
}

static void test_has_suffix(const void *test_data)
{
	const char *str = "string";
	const char *suffix = "ing";

	assert(l_str_has_suffix(str, suffix));
	assert(l_str_has_suffix(str, str));
	assert(!l_str_has_suffix(NULL, suffix));
	assert(!l_str_has_suffix(str, NULL));
	assert(!l_str_has_suffix(suffix, str));
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("l_util_hexstring", test_hexstring, NULL);
	l_test_add("l_util_from_hexstring", test_from_hexstring, NULL);

	l_test_add("l_util_has_suffix", test_has_suffix, NULL);

	return l_test_run();
}
