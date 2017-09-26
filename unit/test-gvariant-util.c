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
#include <math.h>
#include <float.h>
#include <stdio.h>

#include <ell/ell.h>
#include "ell/gvariant-private.h"

struct signature_test {
	bool valid;
	const char *signature;
};

#define SIGNATURE_TEST(v, sig, i)				\
	static struct signature_test sig_test##i = {		\
		.valid = v,					\
		.signature = sig,				\
	}

SIGNATURE_TEST(false, "a", 1);
SIGNATURE_TEST(false, "a{vs}", 2);
SIGNATURE_TEST(true, "(ss)", 3);
SIGNATURE_TEST(true, "(s(ss))", 4);
SIGNATURE_TEST(true, "as", 5);
SIGNATURE_TEST(true, "ab", 6);
SIGNATURE_TEST(true, "aas", 7);
SIGNATURE_TEST(true, "a(ss)", 8);
SIGNATURE_TEST(true, "asas", 9);
SIGNATURE_TEST(true, "av", 10);
SIGNATURE_TEST(true, "a{sv}", 11);
SIGNATURE_TEST(true, "v", 12);
SIGNATURE_TEST(true, "oa{sv}", 13);
SIGNATURE_TEST(true, "a(oa{sv})", 14);
SIGNATURE_TEST(true, "(sa{sv})sa{ss}us", 15);
SIGNATURE_TEST(true, "(bba{ss})", 16);
SIGNATURE_TEST(true, "{sv}", 17);
SIGNATURE_TEST(false, "{vu}", 18);
SIGNATURE_TEST(false, "{uv", 19);
SIGNATURE_TEST(false, "(ss", 20);
SIGNATURE_TEST(false, "aaaaa", 21);
SIGNATURE_TEST(true, "()", 22);
SIGNATURE_TEST(false, "", 23);

static void test_signature(const void *test_data)
{
	const struct signature_test *test = test_data;
	bool valid;

	valid = _gvariant_valid_signature(test->signature);

	assert(valid == test->valid);
}

struct alignment_test {
	int alignment;
	const char *signature;
};

#define ALIGNMENT_TEST(sig, a, i)				\
	static struct alignment_test align_test##i = {		\
		.alignment = a,					\
		.signature = sig,				\
	}

ALIGNMENT_TEST("()", 1, 1);
ALIGNMENT_TEST("y", 1, 2);
ALIGNMENT_TEST("b", 1, 3);
ALIGNMENT_TEST("s", 1, 4);
ALIGNMENT_TEST("o", 1, 5);
ALIGNMENT_TEST("g", 1, 6);
ALIGNMENT_TEST("q", 2, 7);
ALIGNMENT_TEST("n", 2, 8);
ALIGNMENT_TEST("u", 4, 9);
ALIGNMENT_TEST("h", 4, 10);
ALIGNMENT_TEST("i", 4, 11);
ALIGNMENT_TEST("v", 8, 12);
ALIGNMENT_TEST("t", 8, 13);
ALIGNMENT_TEST("x", 8, 14);
ALIGNMENT_TEST("d", 8, 15);
ALIGNMENT_TEST("ay", 1, 16);
ALIGNMENT_TEST("as", 1, 17);
ALIGNMENT_TEST("au", 4, 18);
ALIGNMENT_TEST("an", 2, 19);
ALIGNMENT_TEST("ans", 2, 20);
ALIGNMENT_TEST("ant", 8, 21);
ALIGNMENT_TEST("(ss)", 1, 22);
ALIGNMENT_TEST("(ssu)", 4, 23);
ALIGNMENT_TEST("a(ssu)", 4, 24);
ALIGNMENT_TEST("(u)", 4, 25);
ALIGNMENT_TEST("(uuuuy)", 4, 26);
ALIGNMENT_TEST("(uusuuy)", 4, 27);
ALIGNMENT_TEST("a{ss}", 1, 28);
ALIGNMENT_TEST("((u)yyy(b(iiii)))", 4, 29);
ALIGNMENT_TEST("((u)yyy(b(iiivi)))", 8, 30);
ALIGNMENT_TEST("((b)(t))", 8, 31);
ALIGNMENT_TEST("((b)(b)(t))", 8, 32);
ALIGNMENT_TEST("(bt)", 8, 33);
ALIGNMENT_TEST("((t)(b))", 8, 34);
ALIGNMENT_TEST("(tb)", 8, 35);
ALIGNMENT_TEST("((b)(b))", 1, 36);
ALIGNMENT_TEST("((t)(t))", 8, 37);

static void test_alignment(const void *test_data)
{
	const struct alignment_test *test = test_data;
	int alignment;

	alignment = _gvariant_get_alignment(test->signature);

	assert(alignment == test->alignment);
}

struct is_fixed_size_test {
	bool fixed_size;
	const char *signature;
};

struct get_fixed_size_test {
	int size;
	const char *signature;
};

#define IS_FIXED_SIZE_TEST(sig, v, i)					\
	static struct is_fixed_size_test is_fixed_size_test##i = {	\
		.fixed_size = v,					\
		.signature = sig,					\
	}

IS_FIXED_SIZE_TEST("", true, 1);
IS_FIXED_SIZE_TEST("()", true, 2);
IS_FIXED_SIZE_TEST("y", true, 3);
IS_FIXED_SIZE_TEST("u", true, 4);
IS_FIXED_SIZE_TEST("b", true, 5);
IS_FIXED_SIZE_TEST("n", true, 6);
IS_FIXED_SIZE_TEST("q", true, 7);
IS_FIXED_SIZE_TEST("i", true, 8);
IS_FIXED_SIZE_TEST("t", true, 9);
IS_FIXED_SIZE_TEST("d", true, 10);
IS_FIXED_SIZE_TEST("s", false, 11);
IS_FIXED_SIZE_TEST("o", false, 12);
IS_FIXED_SIZE_TEST("g", false, 13);
IS_FIXED_SIZE_TEST("h", true, 14);
IS_FIXED_SIZE_TEST("ay", false, 15);
IS_FIXED_SIZE_TEST("v", false, 16);
IS_FIXED_SIZE_TEST("(u)", true, 17);
IS_FIXED_SIZE_TEST("(uuuuy)", true, 18);
IS_FIXED_SIZE_TEST("(uusuuy)", false, 19);
IS_FIXED_SIZE_TEST("a{ss}", false, 20);
IS_FIXED_SIZE_TEST("((u)yyy(b(iiii)))", true, 21);
IS_FIXED_SIZE_TEST("((u)yyy(b(iiivi)))", false, 22);

static void test_is_fixed_size(const void *test_data)
{
	const struct is_fixed_size_test *test = test_data;
	bool fixed_size;

	fixed_size = _gvariant_is_fixed_size(test->signature);

	assert(fixed_size == test->fixed_size);
}

#define GET_FIXED_SIZE_TEST(sig, n, i)				\
	static struct get_fixed_size_test size_test##i = {	\
		.size = n,					\
		.signature = sig,				\
	}

GET_FIXED_SIZE_TEST("", 0, 1);
GET_FIXED_SIZE_TEST("()", 1, 2);
GET_FIXED_SIZE_TEST("y", 1, 3);
GET_FIXED_SIZE_TEST("u", 4, 4);
GET_FIXED_SIZE_TEST("b", 1, 5);
GET_FIXED_SIZE_TEST("n", 2, 6);
GET_FIXED_SIZE_TEST("q", 2, 7);
GET_FIXED_SIZE_TEST("i", 4, 8);
GET_FIXED_SIZE_TEST("t", 8, 9);
GET_FIXED_SIZE_TEST("d", 8, 10);
GET_FIXED_SIZE_TEST("s", 0, 11);
GET_FIXED_SIZE_TEST("o", 0, 12);
GET_FIXED_SIZE_TEST("g", 0, 13);
GET_FIXED_SIZE_TEST("h", 4, 14);
GET_FIXED_SIZE_TEST("ay", 0, 15);
GET_FIXED_SIZE_TEST("v", 0, 16);
GET_FIXED_SIZE_TEST("(u)", 4, 17);
GET_FIXED_SIZE_TEST("(uuuuy)", 20, 18);
GET_FIXED_SIZE_TEST("(uusuuy)", 0, 19);
GET_FIXED_SIZE_TEST("a{ss}", 0, 20);
GET_FIXED_SIZE_TEST("((u)yyy(b(iiii)))", 28, 21);
GET_FIXED_SIZE_TEST("((u)yyy(b(iiivi)))", 0, 22);
GET_FIXED_SIZE_TEST("((b)(t))", 16, 23);
GET_FIXED_SIZE_TEST("((b)(b)(t))", 16, 24);
GET_FIXED_SIZE_TEST("(bt)", 16, 25);
GET_FIXED_SIZE_TEST("((t)(b))", 16, 26);
GET_FIXED_SIZE_TEST("(tb)", 16, 27);
GET_FIXED_SIZE_TEST("((b)(b))", 2, 28);
GET_FIXED_SIZE_TEST("((t)(t))", 16, 29);

static void test_get_fixed_size(const void *test_data)
{
	const struct get_fixed_size_test *test = test_data;
	int size;

	size = _gvariant_get_fixed_size(test->signature);

	assert(size == test->size);
}

struct parser_data {
	const unsigned char *data;
	size_t len;
	const char *signature;
};

static const unsigned char basic_data_1[] = {
	0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21,
	0x00,
};

static struct parser_data parser_data_1 = {
	.data = basic_data_1,
	.len = 13,
	.signature = "s",
};

static void test_iter_basic_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct l_dbus_message_iter iter;
	const char *s;

	_gvariant_iter_init(&iter, NULL, test->signature,
				test->signature + strlen(test->signature),
				test->data, test->len);

	assert(_gvariant_iter_next_entry_basic(&iter, 's', &s));
	assert(!strcmp(s, "Hello World!"));
}

static const unsigned char basic_data_2[] = {
	0x05, 0x00, 0x00, 0x00, 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72, 0x00,
};

static struct parser_data parser_data_2 = {
	.data = basic_data_2,
	.len = 11,
	.signature = "is",
};

static void test_iter_basic_2(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct l_dbus_message_iter iter;
	const char *s;
	int i;
	bool ret;

	_gvariant_iter_init(&iter, NULL, test->signature,
				test->signature + strlen(test->signature),
				test->data, test->len);

	ret = _gvariant_iter_next_entry_basic(&iter, 'i', &i);
	assert(ret);
	assert(i == 5);

	ret = _gvariant_iter_next_entry_basic(&iter, 's', &s);
	assert(ret);
	assert(!strcmp(s, "foobar"));
}

static const unsigned char basic_data_3[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x14, 0x40, 0xdf, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x1c, 0xaf, 0x7d, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x21, 0x7f, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xe4, 0xd4, 0x59, 0xfd, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x00, 0x00, 0x00, 0x02, 0xad, 0x31, 0x00, 0x66, 0x6f, 0x6f, 0x62,
	0x61, 0x72, 0x00, 0x00, 0xfe, 0x52, 0xce, 0xff, 0x3f,
};

static struct parser_data parser_data_3 = {
	.data = basic_data_3,
	.len = 69,
	.signature = "bdntqxyusi",
};

static void test_iter_basic_3(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct l_dbus_message_iter iter;
	bool b;
	double d;
	int16_t n;
	uint64_t t;
	uint16_t q;
	int64_t x;
	uint8_t y;
	uint32_t u;
	const char *s;
	int32_t i;
	bool ret;

	_gvariant_iter_init(&iter, NULL, test->signature,
				test->signature + strlen(test->signature),
				test->data, test->len);

	ret = _gvariant_iter_next_entry_basic(&iter, 'd', &b);
	assert(ret == false);

	ret = _gvariant_iter_next_entry_basic(&iter, 'b', &b);
	assert(ret);
	assert(b == true);

	ret = _gvariant_iter_next_entry_basic(&iter, 'd', &d);
	assert(ret);
	assert(fabs(d - 5.0) < DBL_EPSILON);
	assert(d == 5.0);

	ret = _gvariant_iter_next_entry_basic(&iter, 'n', &n);
	assert(ret);
	assert(n == -32545);

	ret = _gvariant_iter_next_entry_basic(&iter, 't', &t);
	assert(ret);
	assert(t == 444444444LL);

	ret = _gvariant_iter_next_entry_basic(&iter, 'q', &q);
	assert(ret);
	assert(q == 32545);

	ret = _gvariant_iter_next_entry_basic(&iter, 'x', &x);
	assert(ret);
	assert(x == -44444444LL);

	ret = _gvariant_iter_next_entry_basic(&iter, 'y', &y);
	assert(ret);
	assert(y == 255);

	ret = _gvariant_iter_next_entry_basic(&iter, 'u', &u);
	assert(ret);
	assert(u == 3255554);

	ret = _gvariant_iter_next_entry_basic(&iter, 's', &s);
	assert(ret);
	assert(!strcmp(s, "foobar"));

	ret = _gvariant_iter_next_entry_basic(&iter, 'i', &i);
	assert(ret);
	assert(i == -3255554);
}

static const unsigned char basic_data_4[] = {
	0x66, 0x6f, 0x6f, 0x00, 0x62, 0x61, 0x72, 0x00,
	0x62, 0x61, 0x7a, 0x00, 0x08, 0x04,
};

static struct parser_data parser_data_4 = {
	.data = basic_data_4,
	.len = 14,
	.signature = "sss",
};

static void test_iter_basic_4(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct l_dbus_message_iter iter;
	const char *s;
	bool ret;

	_gvariant_iter_init(&iter, NULL, test->signature,
				test->signature + strlen(test->signature),
				test->data, test->len);

	ret = _gvariant_iter_next_entry_basic(&iter, 's', &s);
	assert(ret == true);
	assert(!strcmp(s, "foo"));

	ret = _gvariant_iter_next_entry_basic(&iter, 's', &s);
	assert(ret == true);
	assert(!strcmp(s, "bar"));

	ret = _gvariant_iter_next_entry_basic(&iter, 's', &s);
	assert(ret == true);
	assert(!strcmp(s, "baz"));
}

static const unsigned char fixed_struct_data_1[] = {
	0x0a, 0x00, 0x00, 0x00, 0xff, 0x01, 0x00, 0x00,
};

static struct parser_data fixed_struct_1 = {
	.data = fixed_struct_data_1,
	.len = 8,
	.signature = "i(yy)",
};

static void test_iter_fixed_struct_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct l_dbus_message_iter iter;
	int32_t i;
	uint8_t y;
	bool ret;
	struct l_dbus_message_iter structure;

	_gvariant_iter_init(&iter, NULL, test->signature,
				test->signature + strlen(test->signature),
				test->data, test->len);

	ret = _gvariant_iter_next_entry_basic(&iter, 'i', &i);
	assert(ret);
	assert(i == 10);

	ret = _gvariant_iter_enter_struct(&iter, &structure);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&structure, 'y', &y);
	assert(ret);
	assert(y == 255);

	ret = _gvariant_iter_next_entry_basic(&structure, 'y', &y);
	assert(ret);
	assert(y == 1);
}

static const unsigned char fixed_struct_data_2[] = {
	0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb3, 0x15, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0xb3, 0x15, 0x00, 0x00,
};

static struct parser_data fixed_struct_2 = {
	.data = fixed_struct_data_2,
	.len = 24,
	.signature = "(yyt)(yyu)",
};

static void test_iter_fixed_struct_2(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct l_dbus_message_iter iter;
	uint64_t t;
	uint32_t u;
	uint8_t y;
	bool ret;
	struct l_dbus_message_iter structure;

	_gvariant_iter_init(&iter, NULL, test->signature,
				test->signature + strlen(test->signature),
				test->data, test->len);

	ret = _gvariant_iter_enter_struct(&iter, &structure);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&structure, 'y', &y);
	assert(ret);
	assert(y == 1);

	ret = _gvariant_iter_next_entry_basic(&structure, 'y', &y);
	assert(ret);
	assert(y == 2);

	ret = _gvariant_iter_next_entry_basic(&structure, 't', &t);
	assert(ret);
	assert(t == 5555);

	ret = _gvariant_iter_enter_struct(&iter, &structure);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&structure, 'y', &y);
	assert(ret);
	assert(y == 1);

	ret = _gvariant_iter_next_entry_basic(&structure, 'y', &y);
	assert(ret);
	assert(y == 2);

	ret = _gvariant_iter_next_entry_basic(&structure, 'u', &u);
	assert(ret);
	assert(u == 5555);
}

static const unsigned char nested_struct_data_1[] = {
	0x01, 0x00, 0x00, 0x00, 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72, 0x00, 0xff,
	0xff, 0xff, 0xff, 0xff, 0x0b,
};

static struct parser_data nested_struct_1 = {
	.data = nested_struct_data_1,
	.len = 17,
	.signature = "((us)yi)",
};

static void test_iter_nested_struct_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct l_dbus_message_iter iter;
	uint32_t u;
	uint8_t y;
	int32_t i;
	const char *s;
	bool ret;
	struct l_dbus_message_iter outer;
	struct l_dbus_message_iter inner;

	_gvariant_iter_init(&iter, NULL, test->signature,
				test->signature + strlen(test->signature),
				test->data, test->len);

	ret = _gvariant_iter_enter_struct(&iter, &outer);
	assert(ret);

	ret = _gvariant_iter_enter_struct(&outer, &inner);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&inner, 'u', &u);
	assert(ret);
	assert(u == 1);

	ret = _gvariant_iter_next_entry_basic(&inner, 's', &s);
	assert(ret);
	assert(!strcmp(s, "foobar"));

	ret = _gvariant_iter_next_entry_basic(&outer, 'y', &y);
	assert(ret);
	assert(y == 255);

	ret = _gvariant_iter_next_entry_basic(&outer, 'i', &i);
	assert(ret);
	assert(i == -1);
}

static const unsigned char empty_struct_data_1[] = {
	0x00
};

static struct parser_data empty_struct_1 = {
	.data = empty_struct_data_1,
	.len = sizeof(empty_struct_data_1),
	.signature = "()",
};

static void test_iter_empty_struct_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct l_dbus_message_iter iter;
	bool ret;
	struct l_dbus_message_iter str;

	_gvariant_iter_init(&iter, NULL, test->signature,
				test->signature + strlen(test->signature),
				test->data, test->len);

	ret = _gvariant_iter_enter_struct(&iter, &str);
	assert(ret);
	assert(str.sig_len == 0);
}

static const unsigned char variant_data_1[] = {
	0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x66, 0x6f, 0x6f, 0x62,
	0x61, 0x72, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
	0x11, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x19,
};

static struct parser_data variant_1 = {
	.data = variant_data_1,
	.len = 33,
	.signature = "(uvu)i",
};

static void test_iter_variant_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct l_dbus_message_iter iter;
	struct l_dbus_message_iter structure;
	struct l_dbus_message_iter variant;
	int32_t i;
	uint32_t u;
	const char *s;
	bool ret;

	_gvariant_iter_init(&iter, NULL, test->signature,
				test->signature + strlen(test->signature),
				test->data, test->len);

	ret = _gvariant_iter_enter_struct(&iter, &structure);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&structure, 'u', &u);
	assert(ret);
	assert(u == 5);

	ret = _gvariant_iter_enter_variant(&structure, &variant);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&variant, 's', &s);
	assert(ret);
	assert(!strcmp(s, "foobar"));

	ret = _gvariant_iter_next_entry_basic(&structure, 'u', &u);
	assert(ret);
	assert(u == 5);

	ret = _gvariant_iter_next_entry_basic(&iter, 'i', &i);
	assert(ret);
	assert(i == 5);
}

static const unsigned char variant_data_2[] = {
	0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
	0xff, 0x07, 0x00, 0x28, 0x73, 0x75, 0x79, 0x29,
};

static struct parser_data variant_2 = {
	.data = variant_data_2,
	.len = 20,
	.signature = "v",
};

static void test_iter_variant_2(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct l_dbus_message_iter iter;
	struct l_dbus_message_iter variant;
	struct l_dbus_message_iter structure;
	uint8_t y;
	uint32_t u;
	const char *s;
	bool ret;

	_gvariant_iter_init(&iter, NULL, test->signature,
				test->signature + strlen(test->signature),
				test->data, test->len);

	ret = _gvariant_iter_enter_variant(&iter, &variant);
	assert(ret);

	ret = _gvariant_iter_enter_struct(&variant, &structure);

	ret = _gvariant_iter_next_entry_basic(&structure, 's', &s);
	assert(ret);
	assert(!strcmp(s, "foobar"));

	ret = _gvariant_iter_next_entry_basic(&structure, 'u', &u);
	assert(ret);
	assert(u == 20);

	ret = _gvariant_iter_next_entry_basic(&structure, 'y', &y);
	assert(ret);
	assert(y == 255);
}

static const unsigned char fixed_array_data_1[] = {
	0x14, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00,
};

static struct parser_data fixed_array_1 = {
	.data = fixed_array_data_1,
	.len = 8,
	.signature = "au",
};

static void test_iter_fixed_array_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct l_dbus_message_iter iter;
	struct l_dbus_message_iter array;
	uint32_t u;
	bool ret;

	_gvariant_iter_init(&iter, NULL, test->signature,
				test->signature + strlen(test->signature),
				test->data, test->len);

	ret = _gvariant_iter_enter_array(&iter, &array);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&array, 'u', &u);
	assert(ret);
	assert(u == 20);

	ret = _gvariant_iter_next_entry_basic(&array, 'u', &u);
	assert(ret);
	assert(u == 22);

	ret = _gvariant_iter_next_entry_basic(&array, 'u', &u);
	assert(!ret);
}

static const unsigned char variable_array_data_1[] = {
	0x66, 0x6f, 0x6f, 0x00, 0x62, 0x61, 0x72, 0x00, 0x66, 0x6f, 0x6f, 0x62,
	0x61, 0x72, 0x00, 0x04, 0x08, 0x0f,
};

static struct parser_data variable_array_1 = {
	.data = variable_array_data_1,
	.len = 18,
	.signature = "as",
};

static void test_iter_variable_array_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct l_dbus_message_iter iter;
	struct l_dbus_message_iter array;
	const char *s;
	bool ret;

	_gvariant_iter_init(&iter, NULL, test->signature,
				test->signature + strlen(test->signature),
				test->data, test->len);

	ret = _gvariant_iter_enter_array(&iter, &array);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&array, 's', &s);
	assert(ret);
	assert(!strcmp(s, "foo"));

	ret = _gvariant_iter_next_entry_basic(&array, 's', &s);
	assert(ret);
	assert(!strcmp(s, "bar"));

	ret = _gvariant_iter_next_entry_basic(&array, 's', &s);
	assert(ret);
	assert(!strcmp(s, "foobar"));

	ret = _gvariant_iter_next_entry_basic(&array, 's', &s);
	assert(!ret);
}

static const unsigned char variable_array_data_2[] = {
	0x66, 0x6f, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x62, 0x61, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72, 0x31, 0x32, 0x33, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x0a, 0x11, 0x29, 0x49,
};

static struct parser_data variable_array_2 = {
	.data = variable_array_data_2,
	.len = 76,
	.signature = "a(st)",
};

static void test_iter_variable_array_2(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct l_dbus_message_iter iter;
	struct l_dbus_message_iter array;
	struct l_dbus_message_iter structure;
	const char *s;
	uint64_t t;
	bool ret;

	_gvariant_iter_init(&iter, NULL, test->signature,
				test->signature + strlen(test->signature),
				test->data, test->len);

	ret = _gvariant_iter_enter_array(&iter, &array);
	assert(ret);

	ret = _gvariant_iter_enter_struct(&array, &structure);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&structure, 's', &s);
	assert(ret);
	assert(!strcmp(s, "foo"));

	ret = _gvariant_iter_next_entry_basic(&structure, 't', &t);
	assert(ret);
	assert(t == 15LL);

	ret = _gvariant_iter_enter_struct(&array, &structure);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&structure, 's', &s);
	assert(ret);
	assert(!strcmp(s, "bar"));

	ret = _gvariant_iter_next_entry_basic(&structure, 't', &t);
	assert(ret);
	assert(t == 16LL);

	ret = _gvariant_iter_enter_struct(&array, &structure);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&structure, 's', &s);
	assert(ret);
	assert(!strcmp(s, "foobar123"));

	ret = _gvariant_iter_next_entry_basic(&structure, 't', &t);
	assert(ret);
	assert(t == 31LL);
}

static const unsigned char dict_data_1[] = {
	0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
};

static struct parser_data dict_1 = {
	.data = dict_data_1,
	.len = 16,
	.signature = "a{ub}",
};

static void test_iter_dict_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct l_dbus_message_iter iter;
	struct l_dbus_message_iter array;
	struct l_dbus_message_iter structure;
	uint32_t u;
	bool b;
	bool ret;

	_gvariant_iter_init(&iter, NULL, test->signature,
				test->signature + strlen(test->signature),
				test->data, test->len);

	ret = _gvariant_iter_enter_array(&iter, &array);
	assert(ret);

	ret = _gvariant_iter_enter_struct(&array, &structure);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&structure, 'u', &u);
	assert(ret);
	assert(u == 1);

	ret = _gvariant_iter_next_entry_basic(&structure, 'b', &b);
	assert(ret);
	assert(b == true);

	ret = _gvariant_iter_enter_struct(&array, &structure);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&structure, 'u', &u);
	assert(ret);
	assert(u == 2);

	ret = _gvariant_iter_next_entry_basic(&structure, 'b', &b);
	assert(ret);
	assert(b == false);
}

static const unsigned char aau_data_1[] = {
	0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x0c, 0x14, 0x18, 0x18,
};

static struct parser_data aau_1 = {
	.data = aau_data_1,
	.len = 28,
	.signature = "aau",
};

static void test_iter_aau_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct l_dbus_message_iter iter;
	struct l_dbus_message_iter outer;
	struct l_dbus_message_iter inner;
	uint32_t u;
	bool ret;

	_gvariant_iter_init(&iter, NULL, test->signature,
				test->signature + strlen(test->signature),
				test->data, test->len);

	ret = _gvariant_iter_enter_array(&iter, &outer);
	assert(ret);

	ret = _gvariant_iter_enter_array(&outer, &inner);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&inner, 'u', &u);
	assert(ret);
	assert(u == 1);

	ret = _gvariant_iter_next_entry_basic(&inner, 'u', &u);
	assert(ret);
	assert(u == 2);

	ret = _gvariant_iter_next_entry_basic(&inner, 'u', &u);
	assert(ret);
	assert(u == 3);

	ret = _gvariant_iter_next_entry_basic(&inner, 'u', &u);
	assert(!ret);

	ret = _gvariant_iter_enter_array(&outer, &inner);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&inner, 'u', &u);
	assert(ret);
	assert(u == 1);

	ret = _gvariant_iter_next_entry_basic(&inner, 'u', &u);
	assert(ret);
	assert(u == 2);

	ret = _gvariant_iter_next_entry_basic(&inner, 'u', &u);
	assert(!ret);

	ret = _gvariant_iter_enter_array(&outer, &inner);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&inner, 'u', &u);
	assert(ret);
	assert(u == 1);

	ret = _gvariant_iter_next_entry_basic(&inner, 'u', &u);
	assert(!ret);

	ret = _gvariant_iter_enter_array(&outer, &inner);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&inner, 'u', &u);
	assert(!ret);
}

static const unsigned char av_data_1[] = {
	0x46, 0x6f, 0x6f, 0x62, 0x61, 0x72, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x75, 0x09, 0x16,
};

static struct parser_data av_1 = {
	.data = av_data_1,
	.len = 24,
	.signature = "av",
};

static void test_iter_av_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct l_dbus_message_iter iter;
	struct l_dbus_message_iter array;
	struct l_dbus_message_iter variant;
	uint32_t u;
	const char *s;
	bool ret;

	_gvariant_iter_init(&iter, NULL, test->signature,
				test->signature + strlen(test->signature),
				test->data, test->len);

	ret = _gvariant_iter_enter_array(&iter, &array);
	assert(ret);

	ret = _gvariant_iter_enter_variant(&array, &variant);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&variant, 's', &s);
	assert(ret);
	assert(!strcmp(s, "Foobar"));

	ret = _gvariant_iter_enter_variant(&array, &variant);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&variant, 'u', &u);
	assert(ret);
	assert(u == 10);

	ret = _gvariant_iter_enter_variant(&array, &variant);
	assert(!ret);
}

static const unsigned char header_data_1[] = {
	0x6c, 0x01, 0x00, 0x02, 0x28, 0x00, 0x00, 0x00, 0x57, 0x04, 0x00, 0x00,
	0x79, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x2f, 0x66, 0x6f, 0x6f, 0x2f, 0x62, 0x61, 0x72, 0x00, 0x00, 0x6f, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x46, 0x6f, 0x6f, 0x62, 0x61, 0x72, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x66, 0x6f, 0x6f, 0x2e, 0x62, 0x61, 0x72, 0x00, 0x00, 0x73, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x66, 0x6f, 0x6f, 0x2e, 0x62, 0x61, 0x72, 0x00, 0x00, 0x73, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x62, 0x79, 0x6e, 0x71, 0x69, 0x75, 0x78, 0x74, 0x64, 0x00, 0x00, 0x67,
	0x13, 0x29, 0x42, 0x5a, 0x74,
};

static struct parser_data header_1 = {
	.data = header_data_1,
	.len = 137,
	.signature = "a(yv)",
};

static void test_iter_header_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct l_dbus_message_iter iter;
	struct l_dbus_message_iter array;
	struct l_dbus_message_iter structure;
	struct l_dbus_message_iter variant;
	bool ret;
	uint8_t y;
	uint32_t u;
	const char *o;
	const char *s;
	const char *g;

	ret = _gvariant_iter_init(&iter, NULL, "yyyyuuu", NULL,
					test->data, 16);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&iter, 'y', &y);
	assert(ret);
	assert(y == 'l');

	ret = _gvariant_iter_next_entry_basic(&iter, 'y', &y);
	assert(ret);
	assert(y == 1);

	ret = _gvariant_iter_next_entry_basic(&iter, 'y', &y);
	assert(ret);
	assert(y == 0);

	ret = _gvariant_iter_next_entry_basic(&iter, 'y', &y);
	assert(ret);
	assert(y == 2);

	ret = _gvariant_iter_next_entry_basic(&iter, 'u', &u);
	assert(ret);
	assert(u == 40);

	ret = _gvariant_iter_next_entry_basic(&iter, 'u', &u);
	assert(ret);
	assert(u == 1111);

	ret = _gvariant_iter_next_entry_basic(&iter, 'u', &u);
	assert(ret);
	assert(u == 121);

	ret = _gvariant_iter_init(&iter, NULL, "a(yv)", NULL,
					test->data + 16, u);
	ret = _gvariant_iter_enter_array(&iter, &array);
	assert(ret);

	ret = _gvariant_iter_enter_struct(&array, &structure);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&structure, 'y', &y);
	assert(ret);
	assert(y == 1);

	ret = _gvariant_iter_enter_variant(&structure, &variant);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&variant, 'o', &o);
	assert(ret);
	assert(!strcmp(o, "/foo/bar"));

	ret = _gvariant_iter_enter_struct(&array, &structure);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&structure, 'y', &y);
	assert(ret);
	assert(y == 3);

	ret = _gvariant_iter_enter_variant(&structure, &variant);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&variant, 's', &s);
	assert(ret);
	assert(!strcmp(s, "Foobar"));

	ret = _gvariant_iter_enter_struct(&array, &structure);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&structure, 'y', &y);
	assert(ret);
	assert(y == 2);

	ret = _gvariant_iter_enter_variant(&structure, &variant);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&variant, 's', &s);
	assert(ret);
	assert(!strcmp(s, "foo.bar"));

	ret = _gvariant_iter_enter_struct(&array, &structure);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&structure, 'y', &y);
	assert(ret);
	assert(y == 6);

	ret = _gvariant_iter_enter_variant(&structure, &variant);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&variant, 's', &s);
	assert(ret);
	assert(!strcmp(s, "foo.bar"));

	ret = _gvariant_iter_enter_struct(&array, &structure);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&structure, 'y', &y);
	assert(ret);
	assert(y == 8);

	ret = _gvariant_iter_enter_variant(&structure, &variant);
	assert(ret);

	ret = _gvariant_iter_next_entry_basic(&variant, 'g', &g);
	assert(ret);
	assert(!strcmp(g, "bynqiuxtd"));
}

#define BUILDER_TEST_HEADER()\
	void *body;\
	size_t body_size;\
	char *signature\

#define FINISH_AND_CHECK_BUILT_RESULT()\
	signature = _gvariant_builder_finish(builder, &body, &body_size);\
	assert(signature);\
	assert(!strcmp(signature, test->signature));\
	assert(body);\
	assert(body_size == test->len);\
	assert(!memcmp(test->data, body, body_size));\
	l_free(signature);\
	l_free(body);\
	_gvariant_builder_free(builder)\

static void test_builder_basic_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	const char *s = "Hello World!";
	struct dbus_builder *builder;
	bool ret;
	BUILDER_TEST_HEADER();

	builder = _gvariant_builder_new(NULL, 0);
	assert(builder);

	ret = _gvariant_builder_append_basic(builder, 's', s);
	assert(ret);

	FINISH_AND_CHECK_BUILT_RESULT();
}

static void test_builder_basic_2(const void *test_data)
{
	const struct parser_data *test = test_data;
	const char *s = "foobar";
	int i = 5;
	struct dbus_builder *builder;
	bool ret;
	BUILDER_TEST_HEADER();

	builder = _gvariant_builder_new(NULL, 0);
	assert(builder);

	ret = _gvariant_builder_append_basic(builder, 'i', &i);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 's', s);
	assert(ret);

	FINISH_AND_CHECK_BUILT_RESULT();
}

static void test_builder_basic_3(const void *test_data)
{
	const struct parser_data *test = test_data;
	bool b = true;
	double d = 5.0;
	int16_t n = -32545;
	uint64_t t = 444444444LL;
	uint16_t q = 32545;
	int64_t x = -44444444LL;
	uint8_t y = 255;
	uint32_t u = 3255554;
	const char *s = "foobar";
	int32_t i = -3255554;
	struct dbus_builder *builder;
	bool ret;
	BUILDER_TEST_HEADER();

	builder = _gvariant_builder_new(NULL, 0);
	assert(builder);

	ret = _gvariant_builder_append_basic(builder, 'b', &b);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'd', &d);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'n', &n);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 't', &t);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'q', &q);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'x', &x);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'y', &y);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'u', &u);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 's', s);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'i', &i);
	assert(ret);

	FINISH_AND_CHECK_BUILT_RESULT();
}

static void test_builder_basic_4(const void *test_data)
{
	const struct parser_data *test = test_data;
	const char *s1 = "foo";
	const char *s2 = "bar";
	const char *s3 = "baz";
	struct dbus_builder *builder;
	bool ret;
	BUILDER_TEST_HEADER();

	builder = _gvariant_builder_new(NULL, 0);
	assert(builder);

	ret = _gvariant_builder_append_basic(builder, 's', s1);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 's', s2);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 's', s3);
	assert(ret);

	FINISH_AND_CHECK_BUILT_RESULT();
}

static void test_builder_fixed_struct_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	uint32_t i = 10;
	uint8_t y1 = 255;
	uint8_t y2 = 1;
	struct dbus_builder *builder;
	bool ret;
	BUILDER_TEST_HEADER();

	builder = _gvariant_builder_new(NULL, 0);
	assert(builder);

	ret = _gvariant_builder_append_basic(builder, 'i', &i);
	assert(ret);

	ret = _gvariant_builder_enter_struct(builder, "yy");
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'y', &y1);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'y', &y2);
	assert(ret);

	ret = _gvariant_builder_leave_struct(builder);
	assert(ret);

	FINISH_AND_CHECK_BUILT_RESULT();
}

static void test_builder_fixed_struct_2(const void *test_data)
{
	const struct parser_data *test = test_data;
	uint32_t u = 5555;
	uint8_t y1 = 1;
	uint8_t y2 = 2;
	uint64_t t = 5555;
	struct dbus_builder *builder;
	bool ret;
	BUILDER_TEST_HEADER();

	builder = _gvariant_builder_new(NULL, 0);
	assert(builder);

	ret = _gvariant_builder_enter_struct(builder, "yyt");
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'y', &y1);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'y', &y2);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 't', &t);

	ret = _gvariant_builder_leave_struct(builder);
	assert(ret);

	ret = _gvariant_builder_enter_struct(builder, "yyu");
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'y', &y1);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'y', &y2);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'u', &u);
	assert(ret);

	ret = _gvariant_builder_leave_struct(builder);
	assert(ret);

	FINISH_AND_CHECK_BUILT_RESULT();
}

static void test_builder_nested_struct_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	uint32_t u = 1;
	const char *s = "foobar";
	uint8_t y = 255;
	int32_t i = -1;
	struct dbus_builder *builder;
	bool ret;
	BUILDER_TEST_HEADER();

	builder = _gvariant_builder_new(NULL, 0);
	assert(builder);

	ret = _gvariant_builder_enter_struct(builder, "(us)yi");
	assert(ret);

	ret = _gvariant_builder_enter_struct(builder, "us");
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'u', &u);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 's', s);
	assert(ret);

	ret = _gvariant_builder_leave_struct(builder);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'y', &y);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'i', &i);
	assert(ret);

	ret = _gvariant_builder_leave_struct(builder);
	assert(ret);

	FINISH_AND_CHECK_BUILT_RESULT();
}

static void test_builder_empty_struct_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	struct dbus_builder *builder;
	bool ret;
	BUILDER_TEST_HEADER();

	builder = _gvariant_builder_new(NULL, 0);
	assert(builder);

	ret = _gvariant_builder_enter_struct(builder, "");
	assert(ret);

	ret = _gvariant_builder_leave_struct(builder);
	assert(ret);

	FINISH_AND_CHECK_BUILT_RESULT();
}

static void test_builder_variant_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	uint32_t u = 5;
	const char *s = "foobar";
	int32_t i = 5;
	struct dbus_builder *builder;
	bool ret;
	BUILDER_TEST_HEADER();

	builder = _gvariant_builder_new(NULL, 0);
	assert(builder);

	ret = _gvariant_builder_enter_struct(builder, "uvu");
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'u', &u);
	assert(ret);

	ret = _gvariant_builder_enter_variant(builder, "s");
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 's', s);
	assert(ret);

	ret = _gvariant_builder_leave_variant(builder);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'u', &u);
	assert(ret);

	ret = _gvariant_builder_leave_struct(builder);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'i', &i);
	assert(ret);

	FINISH_AND_CHECK_BUILT_RESULT();
}

static void test_builder_variant_2(const void *test_data)
{
	const struct parser_data *test = test_data;
	const char *s = "foobar";
	uint32_t u = 20;
	uint8_t y = 255;
	struct dbus_builder *builder;
	bool ret;
	BUILDER_TEST_HEADER();

	builder = _gvariant_builder_new(NULL, 0);
	assert(builder);

	ret = _gvariant_builder_enter_variant(builder, "(suy)");
	assert(ret);

	ret = _gvariant_builder_enter_struct(builder, "suy");
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 's', s);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'u', &u);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'y', &y);
	assert(ret);

	ret = _gvariant_builder_leave_struct(builder);
	assert(ret);

	ret = _gvariant_builder_leave_variant(builder);
	assert(ret);

	FINISH_AND_CHECK_BUILT_RESULT();
}

static void test_builder_fixed_array_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	uint32_t u1 = 20;
	uint32_t u2 = 22;
	struct dbus_builder *builder;
	bool ret;
	BUILDER_TEST_HEADER();

	builder = _gvariant_builder_new(NULL, 0);
	assert(builder);

	ret = _gvariant_builder_enter_array(builder, "u");
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'u', &u1);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'u', &u2);
	assert(ret);

	ret = _gvariant_builder_leave_array(builder);
	assert(ret);

	FINISH_AND_CHECK_BUILT_RESULT();
}

static void test_builder_dict_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	uint32_t u1 = 1;
	bool b1 = true;
	uint32_t u2 = 2;
	bool b2 = false;
	struct dbus_builder *builder;
	bool ret;
	BUILDER_TEST_HEADER();

	builder = _gvariant_builder_new(NULL, 0);
	assert(builder);

	ret = _gvariant_builder_enter_array(builder, "{ub}");
	assert(ret);

	ret = _gvariant_builder_enter_dict(builder, "ub");
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'u', &u1);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'b', &b1);
	assert(ret);

	ret = _gvariant_builder_leave_dict(builder);
	assert(ret);

	ret = _gvariant_builder_enter_dict(builder, "ub");
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'u', &u2);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 'b', &b2);
	assert(ret);

	ret = _gvariant_builder_leave_dict(builder);
	assert(ret);

	ret = _gvariant_builder_leave_array(builder);
	assert(ret);

	FINISH_AND_CHECK_BUILT_RESULT();
}

static void test_builder_variable_array_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	const char *s1 = "foo";
	const char *s2 = "bar";
	const char *s3 = "foobar";
	struct dbus_builder *builder;
	bool ret;
	BUILDER_TEST_HEADER();

	builder = _gvariant_builder_new(NULL, 0);
	assert(builder);

	ret = _gvariant_builder_enter_array(builder, "s");
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 's', s1);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 's', s2);
	assert(ret);

	ret = _gvariant_builder_append_basic(builder, 's', s3);
	assert(ret);

	ret = _gvariant_builder_leave_array(builder);
	assert(ret);

	FINISH_AND_CHECK_BUILT_RESULT();
}

static void test_builder_variable_array_2(const void *test_data)
{
	const struct parser_data *test = test_data;
	const char *s1 = "foo";
	uint64_t t1 = 15LL;
	const char *s2 = "bar";
	uint64_t t2 = 16LL;
	const char *s3 = "foobar123";
	uint64_t t3 = 31LL;
	struct dbus_builder *builder;
	bool ret;
	BUILDER_TEST_HEADER();

	builder = _gvariant_builder_new(NULL, 0);
	assert(builder);

	ret = _gvariant_builder_enter_array(builder, "(st)");
	assert(ret);

	ret = _gvariant_builder_enter_struct(builder, "st");
	assert(ret);
	ret = _gvariant_builder_append_basic(builder, 's', s1);
	assert(ret);
	ret = _gvariant_builder_append_basic(builder, 't', &t1);
	assert(ret);
	ret = _gvariant_builder_leave_struct(builder);
	assert(ret);

	ret = _gvariant_builder_enter_struct(builder, "st");
	assert(ret);
	ret = _gvariant_builder_append_basic(builder, 's', s2);
	assert(ret);
	ret = _gvariant_builder_append_basic(builder, 't', &t2);
	assert(ret);
	ret = _gvariant_builder_leave_struct(builder);
	assert(ret);

	ret = _gvariant_builder_enter_struct(builder, "st");
	assert(ret);
	ret = _gvariant_builder_append_basic(builder, 's', s3);
	assert(ret);
	ret = _gvariant_builder_append_basic(builder, 't', &t3);
	assert(ret);
	ret = _gvariant_builder_leave_struct(builder);
	assert(ret);

	ret = _gvariant_builder_leave_array(builder);
	assert(ret);

	FINISH_AND_CHECK_BUILT_RESULT();
}

static void test_builder_aau_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	uint32_t u1 = 1;
	uint32_t u2 = 2;
	uint32_t u3 = 3;
	struct dbus_builder *builder;
	bool ret;
	BUILDER_TEST_HEADER();

	builder = _gvariant_builder_new(NULL, 0);
	assert(builder);

	ret = _gvariant_builder_enter_array(builder, "au");
	assert(ret);

	ret = _gvariant_builder_enter_array(builder, "u");
	assert(ret);
	ret = _gvariant_builder_append_basic(builder, 'u', &u1);
	assert(ret);
	ret = _gvariant_builder_append_basic(builder, 'u', &u2);
	assert(ret);
	ret = _gvariant_builder_append_basic(builder, 'u', &u3);
	assert(ret);
	ret = _gvariant_builder_leave_array(builder);
	assert(ret);

	ret = _gvariant_builder_enter_array(builder, "u");
	assert(ret);
	ret = _gvariant_builder_append_basic(builder, 'u', &u1);
	assert(ret);
	ret = _gvariant_builder_append_basic(builder, 'u', &u2);
	assert(ret);
	ret = _gvariant_builder_leave_array(builder);
	assert(ret);

	ret = _gvariant_builder_enter_array(builder, "u");
	assert(ret);
	ret = _gvariant_builder_append_basic(builder, 'u', &u1);
	assert(ret);
	ret = _gvariant_builder_leave_array(builder);
	assert(ret);

	ret = _gvariant_builder_enter_array(builder, "u");
	assert(ret);
	ret = _gvariant_builder_leave_array(builder);
	assert(ret);

	ret = _gvariant_builder_leave_array(builder);
	assert(ret);

	FINISH_AND_CHECK_BUILT_RESULT();
}

static void test_builder_av_1(const void *test_data)
{
	const struct parser_data *test = test_data;
	const char *s = "Foobar";
	uint32_t u = 10;
	struct dbus_builder *builder;
	bool ret;
	BUILDER_TEST_HEADER();

	builder = _gvariant_builder_new(NULL, 0);
	assert(builder);

	ret = _gvariant_builder_enter_array(builder, "v");
	assert(ret);

	ret = _gvariant_builder_enter_variant(builder, "s");
	assert(ret);
	ret = _gvariant_builder_append_basic(builder, 's', s);
	assert(ret);
	ret = _gvariant_builder_leave_variant(builder);
	assert(ret);

	ret = _gvariant_builder_enter_variant(builder, "u");
	assert(ret);
	ret = _gvariant_builder_append_basic(builder, 'u', &u);
	assert(ret);
	ret = _gvariant_builder_leave_variant(builder);
	assert(ret);

	ret = _gvariant_builder_leave_array(builder);
	assert(ret);

	FINISH_AND_CHECK_BUILT_RESULT();
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("Signature Test 1", test_signature, &sig_test1);
	l_test_add("Signature test 2", test_signature, &sig_test2);
	l_test_add("Signature test 3", test_signature, &sig_test3);
	l_test_add("Signature test 4", test_signature, &sig_test4);
	l_test_add("Signature test 5", test_signature, &sig_test5);
	l_test_add("Signature test 6", test_signature, &sig_test6);
	l_test_add("Signature test 7", test_signature, &sig_test7);
	l_test_add("Signature test 8", test_signature, &sig_test8);
	l_test_add("Signature test 9", test_signature, &sig_test9);
	l_test_add("Signature test 10", test_signature, &sig_test10);
	l_test_add("Signature test 11", test_signature, &sig_test11);
	l_test_add("Signature test 12", test_signature, &sig_test12);
	l_test_add("Signature test 13", test_signature, &sig_test13);
	l_test_add("Signature test 14", test_signature, &sig_test14);
	l_test_add("Signature test 15", test_signature, &sig_test15);
	l_test_add("Signature test 16", test_signature, &sig_test16);
	l_test_add("Signature test 17", test_signature, &sig_test17);
	l_test_add("Signature test 18", test_signature, &sig_test18);
	l_test_add("Signature test 19", test_signature, &sig_test19);
	l_test_add("Signature test 20", test_signature, &sig_test20);
	l_test_add("Signature test 21", test_signature, &sig_test21);
	l_test_add("Signature test 22", test_signature, &sig_test22);
	l_test_add("Signature test 23", test_signature, &sig_test23);

	l_test_add("Alignment test 1", test_alignment, &align_test1);
	l_test_add("Alignment test 2", test_alignment, &align_test2);
	l_test_add("Alignment test 3", test_alignment, &align_test3);
	l_test_add("Alignment test 4", test_alignment, &align_test4);
	l_test_add("Alignment test 5", test_alignment, &align_test5);
	l_test_add("Alignment test 6", test_alignment, &align_test6);
	l_test_add("Alignment test 7", test_alignment, &align_test7);
	l_test_add("Alignment test 8", test_alignment, &align_test8);
	l_test_add("Alignment test 9", test_alignment, &align_test9);
	l_test_add("Alignment test 10", test_alignment, &align_test10);
	l_test_add("Alignment test 11", test_alignment, &align_test11);
	l_test_add("Alignment test 12", test_alignment, &align_test12);
	l_test_add("Alignment test 13", test_alignment, &align_test13);
	l_test_add("Alignment test 14", test_alignment, &align_test14);
	l_test_add("Alignment test 15", test_alignment, &align_test15);
	l_test_add("Alignment test 16", test_alignment, &align_test16);
	l_test_add("Alignment test 17", test_alignment, &align_test17);
	l_test_add("Alignment test 18", test_alignment, &align_test18);
	l_test_add("Alignment test 19", test_alignment, &align_test19);
	l_test_add("Alignment test 20", test_alignment, &align_test20);
	l_test_add("Alignment test 21", test_alignment, &align_test21);
	l_test_add("Alignment test 22", test_alignment, &align_test22);
	l_test_add("Alignment test 23", test_alignment, &align_test23);
	l_test_add("Alignment test 24", test_alignment, &align_test24);
	l_test_add("Alignment test 25", test_alignment, &align_test25);
	l_test_add("Alignment test 26", test_alignment, &align_test26);
	l_test_add("Alignment test 27", test_alignment, &align_test27);
	l_test_add("Alignment test 28", test_alignment, &align_test28);
	l_test_add("Alignment test 29", test_alignment, &align_test29);
	l_test_add("Alignment test 30", test_alignment, &align_test30);
	l_test_add("Alignment test 31", test_alignment, &align_test31);
	l_test_add("Alignment test 32", test_alignment, &align_test32);
	l_test_add("Alignment test 33", test_alignment, &align_test33);
	l_test_add("Alignment test 34", test_alignment, &align_test34);
	l_test_add("Alignment test 35", test_alignment, &align_test35);
	l_test_add("Alignment test 36", test_alignment, &align_test36);
	l_test_add("Alignment test 37", test_alignment, &align_test37);

	l_test_add("Is Fixed Size test 1", test_is_fixed_size,
			&is_fixed_size_test1);
	l_test_add("Is Fixed Size test 2", test_is_fixed_size,
			&is_fixed_size_test2);
	l_test_add("Is Fixed Size test 3", test_is_fixed_size,
			&is_fixed_size_test3);
	l_test_add("Is Fixed Size test 4", test_is_fixed_size,
			&is_fixed_size_test4);
	l_test_add("Is Fixed Size test 4", test_is_fixed_size,
			&is_fixed_size_test4);
	l_test_add("Is Fixed Size test 5", test_is_fixed_size,
			&is_fixed_size_test5);
	l_test_add("Is Fixed Size test 6", test_is_fixed_size,
			&is_fixed_size_test6);
	l_test_add("Is Fixed Size test 7", test_is_fixed_size,
			&is_fixed_size_test7);
	l_test_add("Is Fixed Size test 8", test_is_fixed_size,
			&is_fixed_size_test8);
	l_test_add("Is Fixed Size test 9", test_is_fixed_size,
			&is_fixed_size_test9);
	l_test_add("Is Fixed Size test 10", test_is_fixed_size,
			&is_fixed_size_test10);
	l_test_add("Is Fixed Size test 11", test_is_fixed_size,
			&is_fixed_size_test11);
	l_test_add("Is Fixed Size test 12", test_is_fixed_size,
			&is_fixed_size_test12);
	l_test_add("Is Fixed Size test 13", test_is_fixed_size,
			&is_fixed_size_test13);
	l_test_add("Is Fixed Size test 14", test_is_fixed_size,
			&is_fixed_size_test14);
	l_test_add("Is Fixed Size test 15", test_is_fixed_size,
			&is_fixed_size_test15);
	l_test_add("Is Fixed Size test 16", test_is_fixed_size,
			&is_fixed_size_test16);
	l_test_add("Is Fixed Size test 17", test_is_fixed_size,
			&is_fixed_size_test17);
	l_test_add("Is Fixed Size test 18", test_is_fixed_size,
			&is_fixed_size_test18);
	l_test_add("Is Fixed Size test 19", test_is_fixed_size,
			&is_fixed_size_test19);
	l_test_add("Is Fixed Size test 20", test_is_fixed_size,
			&is_fixed_size_test20);
	l_test_add("Is Fixed Size test 21", test_is_fixed_size,
			&is_fixed_size_test21);
	l_test_add("Is Fixed Size test 22", test_is_fixed_size,
			&is_fixed_size_test22);

	l_test_add("Get Fixed Size test 1", test_get_fixed_size, &size_test1);
	l_test_add("Get Fixed Size test 2", test_get_fixed_size, &size_test2);
	l_test_add("Get Fixed Size test 3", test_get_fixed_size, &size_test3);
	l_test_add("Get Fixed Size test 4", test_get_fixed_size, &size_test4);
	l_test_add("Get Fixed Size test 5", test_get_fixed_size, &size_test5);
	l_test_add("Get Fixed Size test 6", test_get_fixed_size, &size_test6);
	l_test_add("Get Fixed Size test 7", test_get_fixed_size, &size_test7);
	l_test_add("Get Fixed Size test 8", test_get_fixed_size, &size_test8);
	l_test_add("Get Fixed Size test 9", test_get_fixed_size, &size_test9);
	l_test_add("Get Fixed Size test 10", test_get_fixed_size, &size_test10);
	l_test_add("Get Fixed Size test 11", test_get_fixed_size, &size_test11);
	l_test_add("Get Fixed Size test 12", test_get_fixed_size, &size_test12);
	l_test_add("Get Fixed Size test 13", test_get_fixed_size, &size_test13);
	l_test_add("Get Fixed Size test 14", test_get_fixed_size, &size_test14);
	l_test_add("Get Fixed Size test 15", test_get_fixed_size, &size_test15);
	l_test_add("Get Fixed Size test 16", test_get_fixed_size, &size_test16);
	l_test_add("Get Fixed Size test 17", test_get_fixed_size, &size_test17);
	l_test_add("Get Fixed Size test 18", test_get_fixed_size, &size_test18);
	l_test_add("Get Fixed Size test 19", test_get_fixed_size, &size_test19);
	l_test_add("Get Fixed Size test 20", test_get_fixed_size, &size_test20);
	l_test_add("Get Fixed Size test 21", test_get_fixed_size, &size_test21);
	l_test_add("Get Fixed Size test 22", test_get_fixed_size, &size_test22);
	l_test_add("Get Fixed Size test 23", test_get_fixed_size, &size_test23);
	l_test_add("Get Fixed Size test 24", test_get_fixed_size, &size_test24);
	l_test_add("Get Fixed Size test 25", test_get_fixed_size, &size_test25);
	l_test_add("Get Fixed Size test 26", test_get_fixed_size, &size_test26);
	l_test_add("Get Fixed Size test 27", test_get_fixed_size, &size_test27);
	l_test_add("Get Fixed Size test 28", test_get_fixed_size, &size_test28);
	l_test_add("Get Fixed Size test 29", test_get_fixed_size, &size_test29);

	l_test_add("Iter Test Basic 's'", test_iter_basic_1, &parser_data_1);
	l_test_add("Iter Test Basic 'is'", test_iter_basic_2, &parser_data_2);
	l_test_add("Iter Test Basic 'bdntqxyusi'",
				test_iter_basic_3, &parser_data_3);
	l_test_add("Iter Test Basic 'sss'", test_iter_basic_4, &parser_data_4);

	l_test_add("Iter Test Fixed Struct 'i(yy)'", test_iter_fixed_struct_1,
			&fixed_struct_1);
	l_test_add("Iter Test Fixed Struct '(yyt)(yyu)'",
			test_iter_fixed_struct_2, &fixed_struct_2);

	l_test_add("Iter Test Nested Struct '((us)yi)'",
			test_iter_nested_struct_1, &nested_struct_1);

	l_test_add("Iter Test Empty Struct '()'",
			test_iter_empty_struct_1, &empty_struct_1);

	l_test_add("Iter Test Variant '(uvu)i'", test_iter_variant_1,
						&variant_1);
	l_test_add("Iter Test Variant 'v'", test_iter_variant_2, &variant_2);

	l_test_add("Iter Test Fixed Array 'au'", test_iter_fixed_array_1,
					&fixed_array_1);
	l_test_add("Iter Test Fixed Dict 'a{ub}'", test_iter_dict_1, &dict_1);

	l_test_add("Iter Test Variable Array 'as'", test_iter_variable_array_1,
					&variable_array_1);
	l_test_add("Iter Test Variable Array 'a(st)'",
				test_iter_variable_array_2, &variable_array_2);

	l_test_add("Iter Test Array of Array 'aau'", test_iter_aau_1, &aau_1);

	l_test_add("Iter Test Array of Variant 'av'", test_iter_av_1, &av_1);

	l_test_add("Iter Test Header 'a(yv)'", test_iter_header_1, &header_1);

	l_test_add("Builder Test Basic 's'", test_builder_basic_1,
					&parser_data_1);
	l_test_add("Builder Test Basic 'is'", test_builder_basic_2,
					&parser_data_2);
	l_test_add("Builder Test Basic 'bdntqxyusi'", test_builder_basic_3,
					&parser_data_3);
	l_test_add("Builder Test Basic 'sss'", test_builder_basic_4,
					&parser_data_4);

	l_test_add("Builder Test Fixed Struct 'i(yy)'",
			test_builder_fixed_struct_1, &fixed_struct_1);
	l_test_add("Builder Test Fixed Struct '(yyt)(yyu)'",
			test_builder_fixed_struct_2, &fixed_struct_2);

	l_test_add("Builder Test Nested Struct '((us)yi)'",
			test_builder_nested_struct_1, &nested_struct_1);

	l_test_add("Builder Test Empty Struct '()'",
			test_builder_empty_struct_1, &empty_struct_1);

	l_test_add("Builder Test Variant '(uvu)i'", test_builder_variant_1,
						&variant_1);
	l_test_add("Builder Test Variant 'v'", test_builder_variant_2,
						&variant_2);

	l_test_add("Builder Test Fixed Array 'au'", test_builder_fixed_array_1,
					&fixed_array_1);
	l_test_add("Builder Test Fixed Dict 'a{ub}'", test_builder_dict_1,
					&dict_1);
	l_test_add("Builder Test Variable Array 'as'",
				test_builder_variable_array_1,
				&variable_array_1);
	l_test_add("Builder Test Variable Array 'a(st)'",
				test_builder_variable_array_2,
				&variable_array_2);

	l_test_add("Builder Test Array of Array 'aau'",
				test_builder_aau_1, &aau_1);

	l_test_add("Builder Test Array of Variant 'av'",
				test_builder_av_1, &av_1);

	return l_test_run();
}
