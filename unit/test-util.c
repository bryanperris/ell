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

static void do_strlcpy(size_t dst_bytes, size_t src_bytes)
{
	/* A valid address is needed for the destination buffer
	 * even if l_strlcpy is told to not copy anything there
	 */
	char *dst = l_malloc(dst_bytes ?: 1);
	char *src = l_malloc(src_bytes);
	size_t src_strlen = src_bytes - 1;

	memset(dst, ' ', dst_bytes ?: 1);
	memset(src, '@', src_strlen);
	src[src_strlen] = '\0';

	assert(l_strlcpy(dst, src, dst_bytes) == src_strlen);

	if (!dst_bytes) {
		assert(*dst == ' ');
	} else if (src_strlen >= dst_bytes) {
		/* Copy was truncated */
		assert(strlen(dst) == dst_bytes - 1);
		assert(l_str_has_prefix(src, dst));
	} else
		assert(!strcmp(src, dst));

	l_free(dst);
	l_free(src);
}

static void test_strlcpy(const void *test_data)
{
	do_strlcpy(0, 1);
	do_strlcpy(0, 10);
	do_strlcpy(10, 8);
	do_strlcpy(10, 9);
	do_strlcpy(10, 10);
	do_strlcpy(10, 11);
	do_strlcpy(10, 12);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("l_util_hexstring", test_hexstring, NULL);
	l_test_add("l_util_from_hexstring", test_from_hexstring, NULL);

	l_test_add("l_util_has_suffix", test_has_suffix, NULL);

	l_test_add("l_strlcpy", test_strlcpy, NULL);

	return l_test_run();
}
