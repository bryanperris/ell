/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2014  Intel Corporation. All rights reserved.
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

	return l_test_run();
}
