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

enum utf8_validate_type {
	UTF8_VALIDATE_TYPE_VALID,
	UTF8_VALIDATE_TYPE_INCOMPLETE,
	UTF8_VALIDATE_TYPE_NOTUNICODE,
	UTF8_VALIDATE_TYPE_OVERLONG,
	UTF8_VALIDATE_TYPE_MALFORMED,
};

struct utf8_validate_test {
	const char *utf8;
	size_t utf8_len;
	enum utf8_validate_type type;
	const wchar_t *ucs4;
	size_t ucs4_len;
};

static const char utf8_1[] = {
			0xce, 0xba, 0xe1, 0xbd, 0xb9, 0xcf, 0x83, 0xce,
			0xbc, 0xce, 0xb5 };
static const wchar_t ucs4_1[] = { 0x03ba, 0x1f79, 0x03c3, 0x03bc, 0x03b5 };

static struct utf8_validate_test utf8_validate_test1 = {
	.utf8 = utf8_1,
	.utf8_len = 11,
	.type = UTF8_VALIDATE_TYPE_VALID,
	.ucs4 = ucs4_1,
	.ucs4_len = 5,
};

static const char utf8_2[] = { 0xc2, 0x80 };
static const wchar_t ucs4_2[] = { 0x0080 };

static struct utf8_validate_test utf8_validate_test2 = {
	.utf8 = utf8_2,
	.utf8_len = 2,
	.type = UTF8_VALIDATE_TYPE_VALID,
	.ucs4 = ucs4_2,
	.ucs4_len = 1,
};

static const char utf8_3[] = { 0xe0, 0xa0, 0x80 };
static const wchar_t ucs4_3[] = { 0x0800 };

static struct utf8_validate_test utf8_validate_test3 = {
	.utf8 = utf8_3,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_VALID,
	.ucs4 = ucs4_3,
	.ucs4_len = 1,
};

static const char utf8_4[] = { 0xf0, 0x90, 0x80, 0x80 };
static const wchar_t ucs4_4[] = { 0x00010000 };

static struct utf8_validate_test utf8_validate_test4 = {
	.utf8 = utf8_4,
	.utf8_len = 4,
	.type = UTF8_VALIDATE_TYPE_VALID,
	.ucs4 = ucs4_4,
	.ucs4_len = 1,
};

static const char utf8_5[] = { 0xf8, 0x88, 0x80, 0x80, 0x80 };
static const wchar_t ucs4_5[] = { 0x00200000 };

static struct utf8_validate_test utf8_validate_test5 = {
	.utf8 = utf8_5,
	.utf8_len = 5,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_5,
	.ucs4_len = 1,
};

static const char utf8_6[] = { 0xfc, 0x84, 0x80, 0x80, 0x80, 0x80 };
static const wchar_t ucs4_6[] = { 0x04000000 };

static struct utf8_validate_test utf8_validate_test6 = {
	.utf8 = utf8_6,
	.utf8_len = 6,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_6,
	.ucs4_len = 1,
};

static const char utf8_7[] = { 0x7f };
static const wchar_t ucs4_7[] = { 0x0000007f };

static struct utf8_validate_test utf8_validate_test7 = {
	.utf8 = utf8_7,
	.utf8_len = 1,
	.type = UTF8_VALIDATE_TYPE_VALID,
	.ucs4 = ucs4_7,
	.ucs4_len = 1,
};

static const char utf8_8[] = { 0xdf, 0xbf };
static const wchar_t ucs4_8[] = { 0x000007ff };

static struct utf8_validate_test utf8_validate_test8 = {
	.utf8 = utf8_8,
	.utf8_len = 2,
	.type = UTF8_VALIDATE_TYPE_VALID,
	.ucs4 = ucs4_8,
	.ucs4_len = 1,
};

static const char utf8_9[] = { 0xef, 0xbf, 0xbf };
static const wchar_t ucs4_9[] = { 0x0000ffff };

static struct utf8_validate_test utf8_validate_test9 = {
	.utf8 = utf8_9,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_9,
	.ucs4_len = 1,
};

static const char utf8_10[] = { 0xf7, 0xbf, 0xbf, 0xbf };
static const wchar_t ucs4_10[] = { 0x001fffff };

static struct utf8_validate_test utf8_validate_test10 = {
	.utf8 = utf8_10,
	.utf8_len = 4,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_10,
	.ucs4_len = 1,
};

static const char utf8_11[] = { 0xfb, 0xbf, 0xbf, 0xbf, 0xbf };
static const wchar_t ucs4_11[] = { 0x03ffffff };

static struct utf8_validate_test utf8_validate_test11 = {
	.utf8 = utf8_11,
	.utf8_len = 5,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_11,
	.ucs4_len = 1,
};

static const char utf8_12[] = { 0xfd, 0xbf, 0xbf, 0xbf, 0xbf, 0xbf };
static const wchar_t ucs4_12[] = { 0x7fffffff };

static struct utf8_validate_test utf8_validate_test12 = {
	.utf8 = utf8_12,
	.utf8_len = 6,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_12,
	.ucs4_len = 1,
};

static const char utf8_13[] = { 0xed, 0x9f, 0xbf };
static const wchar_t ucs4_13[] = { 0xd7ff };

static struct utf8_validate_test utf8_validate_test13 = {
	.utf8 = utf8_13,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_VALID,
	.ucs4 = ucs4_13,
	.ucs4_len = 1,
};

static const char utf8_14[] = { 0xee, 0x80, 0x80 };
static const wchar_t ucs4_14[] = { 0xe000 };

static struct utf8_validate_test utf8_validate_test14 = {
	.utf8 = utf8_14,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_VALID,
	.ucs4 = ucs4_14,
	.ucs4_len = 1,
};

static const char utf8_15[] = { 0xef, 0xbf, 0xbd };
static const wchar_t ucs4_15[] = { 0xfffd };

static struct utf8_validate_test utf8_validate_test15 = {
	.utf8 = utf8_15,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_VALID,
	.ucs4 = ucs4_15,
	.ucs4_len = 1,
};

static const char utf8_16[] = { 0xf4, 0x8f, 0xbf, 0xbd };
static const wchar_t ucs4_16[] = { 0x0010fffd };

static struct utf8_validate_test utf8_validate_test16 = {
	.utf8 = utf8_16,
	.utf8_len = 4,
	.type = UTF8_VALIDATE_TYPE_VALID,
	.ucs4 = ucs4_16,
	.ucs4_len = 1,
};

static const char utf8_17[] = { 0xf4, 0x8f, 0xbf, 0xbf };
static const wchar_t ucs4_17[] = { 0x0010ffff };

static struct utf8_validate_test utf8_validate_test17 = {
	.utf8 = utf8_17,
	.utf8_len = 4,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_17,
	.ucs4_len = 1,
};

static const char utf8_18[] = { 0xf4, 0x90, 0x80, 0x80 };
static const wchar_t ucs4_18[] = { 0x00110000 };

static struct utf8_validate_test utf8_validate_test18 = {
	.utf8 = utf8_18,
	.utf8_len = 4,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_18,
	.ucs4_len = 1,
};

static const char utf8_19[] = { 0x80 };

static struct utf8_validate_test utf8_validate_test19 = {
	.utf8 = utf8_19,
	.utf8_len = 1,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_20[] = { 0xbf };

static struct utf8_validate_test utf8_validate_test20 = {
	.utf8 = utf8_20,
	.utf8_len = 1,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_21[] = { 0x80, 0xbf };

static struct utf8_validate_test utf8_validate_test21 = {
	.utf8 = utf8_21,
	.utf8_len = 2,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_22[] = { 0x80, 0xbf, 0x80 };

static struct utf8_validate_test utf8_validate_test22 = {
	.utf8 = utf8_22,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_23[] = { 0x80, 0xbf, 0x80, 0xbf };

static struct utf8_validate_test utf8_validate_test23 = {
	.utf8 = utf8_23,
	.utf8_len = 4,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_24[] = { 0x80, 0xbf, 0x80, 0xbf, 0x80 };

static struct utf8_validate_test utf8_validate_test24 = {
	.utf8 = utf8_24,
	.utf8_len = 5,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_25[] = { 0x80, 0xbf, 0x80, 0xbf, 0x80, 0xbf };

static struct utf8_validate_test utf8_validate_test25 = {
	.utf8 = utf8_25,
	.utf8_len = 6,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_26[] = { 0x80, 0xbf, 0x80, 0xbf, 0x80, 0xbf, 0x80 };

static struct utf8_validate_test utf8_validate_test26 = {
	.utf8 = utf8_26,
	.utf8_len = 7,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_27[] = {
			0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
			0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
			0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
			0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
			0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
			0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
			0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
			0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf };

static struct utf8_validate_test utf8_validate_test27 = {
	.utf8 = utf8_27,
	.utf8_len = 63,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_28[] = {
			0xc0, 0x20, 0xc1, 0x20, 0xc2, 0x20, 0xc3, 0x20,
			0xc4, 0x20, 0xc5, 0x20, 0xc6, 0x20, 0xc7, 0x20,
			0xc8, 0x20, 0xc9, 0x20, 0xca, 0x20, 0xcb, 0x20,
			0xcc, 0x20, 0xcd, 0x20, 0xce, 0x20, 0xcf, 0x20,
			0xd0, 0x20, 0xd1, 0x20, 0xd2, 0x20, 0xd3, 0x20,
			0xd4, 0x20, 0xd5, 0x20, 0xd6, 0x20, 0xd7, 0x20,
			0xd8, 0x20, 0xd9, 0x20, 0xda, 0x20, 0xdb, 0x20,
			0xdc, 0x20, 0xdd, 0x20, 0xde, 0x20, 0xdf, 0x20 };

static struct utf8_validate_test utf8_validate_test28 = {
	.utf8 = utf8_28,
	.utf8_len = 64,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_29[] = {
			0xe0, 0x20, 0xe1, 0x20, 0xe2, 0x20, 0xe3, 0x20,
			0xe4, 0x20, 0xe5, 0x20, 0xe6, 0x20, 0xe7, 0x20,
			0xe8, 0x20, 0xe9, 0x20, 0xea, 0x20, 0xeb, 0x20,
			0xec, 0x20, 0xed, 0x20, 0xee, 0x20, 0xef, 0x20 };

static struct utf8_validate_test utf8_validate_test29 = {
	.utf8 = utf8_29,
	.utf8_len = 32,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_30[] = {
			0xf0, 0x20, 0xf1, 0x20, 0xf2, 0x20, 0xf3, 0x20,
			0xf4, 0x20, 0xf5, 0x20, 0xf6, 0x20, 0xf7, 0x20 };

static struct utf8_validate_test utf8_validate_test30 = {
	.utf8 = utf8_30,
	.utf8_len = 16,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_31[] = {
			0xf8, 0x20, 0xf9, 0x20, 0xfa, 0x20, 0xfb, 0x20 };

static struct utf8_validate_test utf8_validate_test31 = {
	.utf8 = utf8_31,
	.utf8_len = 8,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_32[] = { 0xfc, 0x20, 0xfd, 0x20 };

static struct utf8_validate_test utf8_validate_test32 = {
	.utf8 = utf8_32,
	.utf8_len = 4,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_33[] = { 0xc0 };

static struct utf8_validate_test utf8_validate_test33 = {
	.utf8 = utf8_33,
	.utf8_len = 1,
	.type = UTF8_VALIDATE_TYPE_INCOMPLETE,
};

static const char utf8_34[] = { 0xe0, 0x80 };

static struct utf8_validate_test utf8_validate_test34 = {
	.utf8 = utf8_34,
	.utf8_len = 2,
	.type = UTF8_VALIDATE_TYPE_INCOMPLETE,
};

static const char utf8_35[] = { 0xf0, 0x80, 0x80 };

static struct utf8_validate_test utf8_validate_test35 = {
	.utf8 = utf8_35,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_INCOMPLETE,
};

static const char utf8_36[] = { 0xf8, 0x80, 0x80, 0x80 };

static struct utf8_validate_test utf8_validate_test36 = {
	.utf8 = utf8_36,
	.utf8_len = 4,
	.type = UTF8_VALIDATE_TYPE_INCOMPLETE,
};

static const char utf8_37[] = { 0xfc, 0x80, 0x80, 0x80, 0x80 };

static struct utf8_validate_test utf8_validate_test37 = {
	.utf8 = utf8_37,
	.utf8_len = 5,
	.type = UTF8_VALIDATE_TYPE_INCOMPLETE,
};

static const char utf8_38[] = { 0xdf };

static struct utf8_validate_test utf8_validate_test38 = {
	.utf8 = utf8_38,
	.utf8_len = 1,
	.type = UTF8_VALIDATE_TYPE_INCOMPLETE,
};

static const char utf8_39[] = { 0xef, 0xbf };

static struct utf8_validate_test utf8_validate_test39 = {
	.utf8 = utf8_39,
	.utf8_len = 2,
	.type = UTF8_VALIDATE_TYPE_INCOMPLETE,
};

static const char utf8_40[] = { 0xf7, 0xbf, 0xbf };

static struct utf8_validate_test utf8_validate_test40 = {
	.utf8 = utf8_40,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_INCOMPLETE,
};

static const char utf8_41[] = { 0xfb, 0xbf, 0xbf, 0xbf };

static struct utf8_validate_test utf8_validate_test41 = {
	.utf8 = utf8_41,
	.utf8_len = 4,
	.type = UTF8_VALIDATE_TYPE_INCOMPLETE,
};

static const char utf8_42[] = { 0xfd, 0xbf, 0xbf, 0xbf, 0xbf };

static struct utf8_validate_test utf8_validate_test42 = {
	.utf8 = utf8_42,
	.utf8_len = 5,
	.type = UTF8_VALIDATE_TYPE_INCOMPLETE,
};

static const char utf8_43[] = {
			0xc0, 0xe0, 0x80, 0xf0, 0x80, 0x80, 0xf8, 0x80,
			0x80, 0x80, 0xfc, 0x80, 0x80, 0x80, 0x80, 0xdf,
			0xef, 0xbf, 0xf7, 0xbf, 0xbf, 0xfb, 0xbf, 0xbf,
			0xbf, 0xfd, 0xbf, 0xbf, 0xbf, 0xbf };

static struct utf8_validate_test utf8_validate_test43 = {
	.utf8 = utf8_43,
	.utf8_len = 30,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_44[] = { 0xfe };

static struct utf8_validate_test utf8_validate_test44 = {
	.utf8 = utf8_44,
	.utf8_len = 1,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_45[] = { 0xff };

static struct utf8_validate_test utf8_validate_test45 = {
	.utf8 = utf8_45,
	.utf8_len = 1,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_46[] = { 0xfe, 0xfe, 0xff, 0xff };

static struct utf8_validate_test utf8_validate_test46 = {
	.utf8 = utf8_46,
	.utf8_len = 4,
	.type = UTF8_VALIDATE_TYPE_MALFORMED,
};

static const char utf8_47[] = { 0xc0, 0xaf };

static struct utf8_validate_test utf8_validate_test47 = {
	.utf8 = utf8_47,
	.utf8_len = 2,
	.type = UTF8_VALIDATE_TYPE_OVERLONG,
};

static const char utf8_48[] = { 0xe0, 0x80, 0xaf };

static struct utf8_validate_test utf8_validate_test48 = {
	.utf8 = utf8_48,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_OVERLONG,
};

static const char utf8_49[] = { 0xf0, 0x80, 0x80, 0xaf };

static struct utf8_validate_test utf8_validate_test49 = {
	.utf8 = utf8_49,
	.utf8_len = 4,
	.type = UTF8_VALIDATE_TYPE_OVERLONG,
};

static const char utf8_50[] = { 0xf8, 0x80, 0x80, 0x80, 0xaf };

static struct utf8_validate_test utf8_validate_test50 = {
	.utf8 = utf8_50,
	.utf8_len = 5,
	.type = UTF8_VALIDATE_TYPE_OVERLONG,
};

static const char utf8_51[] = { 0xfc, 0x80, 0x80, 0x80, 0x80, 0xaf };

static struct utf8_validate_test utf8_validate_test51 = {
	.utf8 = utf8_51,
	.utf8_len = 6,
	.type = UTF8_VALIDATE_TYPE_OVERLONG,
};

static const char utf8_52[] = { 0xc1, 0xbf };

static struct utf8_validate_test utf8_validate_test52 = {
	.utf8 = utf8_52,
	.utf8_len = 2,
	.type = UTF8_VALIDATE_TYPE_OVERLONG,
};

static const char utf8_53[] = { 0xe0, 0x9f, 0xbf };

static struct utf8_validate_test utf8_validate_test53 = {
	.utf8 = utf8_53,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_OVERLONG,
};

static const char utf8_54[] = { 0xf0, 0x8f, 0xbf, 0xbf };

static struct utf8_validate_test utf8_validate_test54 = {
	.utf8 = utf8_54,
	.utf8_len = 4,
	.type = UTF8_VALIDATE_TYPE_OVERLONG,
};

static const char utf8_55[] = { 0xf8, 0x87, 0xbf, 0xbf, 0xbf };

static struct utf8_validate_test utf8_validate_test55 = {
	.utf8 = utf8_55,
	.utf8_len = 5,
	.type = UTF8_VALIDATE_TYPE_OVERLONG,
};

static const char utf8_56[] = { 0xfc, 0x83, 0xbf, 0xbf, 0xbf, 0xbf };

static struct utf8_validate_test utf8_validate_test56 = {
	.utf8 = utf8_56,
	.utf8_len = 6,
	.type = UTF8_VALIDATE_TYPE_OVERLONG,
};

static const char utf8_57[] = { 0xc0, 0x80 };

static struct utf8_validate_test utf8_validate_test57 = {
	.utf8 = utf8_57,
	.utf8_len = 2,
	.type = UTF8_VALIDATE_TYPE_OVERLONG,
};

static const char utf8_58[] = { 0xe0, 0x80, 0x80 };

static struct utf8_validate_test utf8_validate_test58 = {
	.utf8 = utf8_58,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_OVERLONG,
};

static const char utf8_59[] = { 0xf0, 0x80, 0x80, 0x80 };

static struct utf8_validate_test utf8_validate_test59 = {
	.utf8 = utf8_59,
	.utf8_len = 4,
	.type = UTF8_VALIDATE_TYPE_OVERLONG,
};

static const char utf8_60[] = { 0xf8, 0x80, 0x80, 0x80, 0x80 };

static struct utf8_validate_test utf8_validate_test60 = {
	.utf8 = utf8_60,
	.utf8_len = 5,
	.type = UTF8_VALIDATE_TYPE_OVERLONG,
};

static const char utf8_61[] = { 0xfc, 0x80, 0x80, 0x80, 0x80, 0x80 };

static struct utf8_validate_test utf8_validate_test61 = {
	.utf8 = utf8_61,
	.utf8_len = 6,
	.type = UTF8_VALIDATE_TYPE_OVERLONG,
};

static const char utf8_62[] = { 0xed, 0xa0, 0x80 };
static const wchar_t ucs4_62[] = { 0xd800 };

static struct utf8_validate_test utf8_validate_test62 = {
	.utf8 = utf8_62,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_62,
	.ucs4_len = 1,
};

static const char utf8_63[] = { 0xed, 0xad, 0xbf };
static const wchar_t ucs4_63[] = { 0xdb7f };

static struct utf8_validate_test utf8_validate_test63 = {
	.utf8 = utf8_63,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_63,
	.ucs4_len = 1,
};

static const char utf8_64[] = { 0xed, 0xae, 0x80 };
static const wchar_t ucs4_64[] = { 0xdb80 };

static struct utf8_validate_test utf8_validate_test64 = {
	.utf8 = utf8_64,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_64,
	.ucs4_len = 1,
};

static const char utf8_65[] = { 0xed, 0xaf, 0xbf };
static const wchar_t ucs4_65[] = { 0xdbff };

static struct utf8_validate_test utf8_validate_test65 = {
	.utf8 = utf8_65,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_65,
	.ucs4_len = 1,
};

static const char utf8_66[] = { 0xed, 0xb0, 0x80 };
static const wchar_t ucs4_66[] = { 0xdc00 };

static struct utf8_validate_test utf8_validate_test66 = {
	.utf8 = utf8_66,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_66,
	.ucs4_len = 1,
};

static const char utf8_67[] = { 0xed, 0xbe, 0x80 };
static const wchar_t ucs4_67[] = { 0xdf80 };

static struct utf8_validate_test utf8_validate_test67 = {
	.utf8 = utf8_67,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_67,
	.ucs4_len = 1,
};

static const char utf8_68[] = { 0xed, 0xbf, 0xbf };
static const wchar_t ucs4_68[] = { 0xdfff };

static struct utf8_validate_test utf8_validate_test68 = {
	.utf8 = utf8_68,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_68,
	.ucs4_len = 1,
};

static const char utf8_69[] = { 0xed, 0xa0, 0x80, 0xed, 0xb0, 0x80 };
static const wchar_t ucs4_69[] = { 0xd800, 0xdc00 };

static struct utf8_validate_test utf8_validate_test69 = {
	.utf8 = utf8_69,
	.utf8_len = 6,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_69,
	.ucs4_len = 2,
};

static const char utf8_70[] = { 0xed, 0xa0, 0x80, 0xed, 0xbf, 0xbf };
static const wchar_t ucs4_70[] = { 0xd800, 0xdfff };

static struct utf8_validate_test utf8_validate_test70 = {
	.utf8 = utf8_70,
	.utf8_len = 6,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_70,
	.ucs4_len = 2,
};

static const char utf8_71[] = { 0xed, 0xad, 0xbf, 0xed, 0xb0, 0x80 };
static const wchar_t ucs4_71[] = { 0xdb7f, 0xdc00 };

static struct utf8_validate_test utf8_validate_test71 = {
	.utf8 = utf8_71,
	.utf8_len = 6,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_71,
	.ucs4_len = 2,
};

static const char utf8_72[] = { 0xed, 0xad, 0xbf, 0xed, 0xbf, 0xbf };
static const wchar_t ucs4_72[] = { 0xdb7f, 0xdfff };

static struct utf8_validate_test utf8_validate_test72 = {
	.utf8 = utf8_72,
	.utf8_len = 6,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_72,
	.ucs4_len = 2,
};

static const char utf8_73[] = { 0xed, 0xae, 0x80, 0xed, 0xb0, 0x80 };
static const wchar_t ucs4_73[] = { 0xdb80, 0xdc00 };

static struct utf8_validate_test utf8_validate_test73 = {
	.utf8 = utf8_73,
	.utf8_len = 6,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_73,
	.ucs4_len = 2,
};

static const char utf8_74[] = { 0xed, 0xae, 0x80, 0xed, 0xbf, 0xbf };
static const wchar_t ucs4_74[] = { 0xdb80, 0xdfff };

static struct utf8_validate_test utf8_validate_test74 = {
	.utf8 = utf8_74,
	.utf8_len = 6,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_74,
	.ucs4_len = 2,
};

static const char utf8_75[] = { 0xed, 0xaf, 0xbf, 0xed, 0xb0, 0x80 };
static const wchar_t ucs4_75[] = { 0xdbff, 0xdc00 };

static struct utf8_validate_test utf8_validate_test75 = {
	.utf8 = utf8_75,
	.utf8_len = 6,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_75,
	.ucs4_len = 2,
};

static const char utf8_76[] = { 0xed, 0xaf, 0xbf, 0xed, 0xbf, 0xbf };
static const wchar_t ucs4_76[] = { 0xdbff, 0xdfff };

static struct utf8_validate_test utf8_validate_test76 = {
	.utf8 = utf8_76,
	.utf8_len = 6,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_76,
	.ucs4_len = 2,
};

static const char utf8_77[] = { 0xef, 0xbf, 0xbe };
static const wchar_t ucs4_77[] = { 0xfffe };

static struct utf8_validate_test utf8_validate_test77 = {
	.utf8 = utf8_77,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_77,
	.ucs4_len = 1,
};

static const char utf8_78[] = { 0xef, 0xbf, 0xbf };
static const wchar_t ucs4_78[] = { 0xffff };

static struct utf8_validate_test utf8_validate_test78 = {
	.utf8 = utf8_78,
	.utf8_len = 3,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_78,
	.ucs4_len = 1,
};

static const char utf8_79[] = {
			0x41, 0xf0, 0x90, 0x80, 0x80, 0x42, 0xf4, 0x8f,
			0xbf, 0xbd, 0x43 };
static const wchar_t ucs4_79[] = { 0x41, 0x00010000, 0x42, 0x10fffd, 0x43 };

static struct utf8_validate_test utf8_validate_test79 = {
	.utf8 = utf8_79,
	.utf8_len = 11,
	.type = UTF8_VALIDATE_TYPE_VALID,
	.ucs4 = ucs4_79,
	.ucs4_len = 5,
};

static const char utf8_80[] = { 0xdf, 0x65 };
static const wchar_t ucs4_80[] = { 0xffff };

static struct utf8_validate_test utf8_validate_test80 = {
	.utf8 = utf8_80,
	.utf8_len = 2,
	.type = UTF8_VALIDATE_TYPE_NOTUNICODE,
	.ucs4 = ucs4_80,
	.ucs4_len = 1,
};

static void test_utf8_codepoint(const struct utf8_validate_test *test)
{
	unsigned int i, pos;
	int ret;
	wchar_t val;

	for (i = 0, pos = 0; i < test->ucs4_len; ++i) {
		ret = l_utf8_get_codepoint(test->utf8 + pos,
						test->utf8_len - pos, &val);
		assert(ret > 0 && val == test->ucs4[i]);
		pos += ret;
	}
}

static void test_utf8_validate(const void *test_data)
{
	const struct utf8_validate_test *test = test_data;
	const char *end;
	bool res;

	res = l_utf8_validate(test->utf8, test->utf8_len, &end);

	if (test->type == UTF8_VALIDATE_TYPE_VALID)
		assert(res == true);
	else
		assert(res == false);

	if (test->type == UTF8_VALIDATE_TYPE_VALID && test->ucs4_len) {
		test_utf8_codepoint(test);
	}
}

struct utf8_strlen_test {
	const char *utf8;
	size_t utf8_len;
};

static struct utf8_strlen_test utf8_strlen_test1 = {
	.utf8 = "abc\xce\xba\xe1\xbd\xb9\xcf\x83\xce\xbc\xce\xb5",
	.utf8_len = 8,
};

static void test_utf8_strlen(const void *test_data)
{
	const struct utf8_strlen_test *test = test_data;
	size_t len;

	len = l_utf8_strlen(test->utf8);
	assert(len == test->utf8_len);
}

struct utf8_from_utf16_test {
	uint16_t utf16[64];
	size_t utf16_size;
	const char *utf8;
};

static struct utf8_from_utf16_test utf8_from_utf16_test1 = {
	.utf16 = { 0x61, 0x62, 0x63, 0x00 },
	.utf16_size = 8,
	.utf8 = "abc",
};

static struct utf8_from_utf16_test utf8_from_utf16_test2 = {
	.utf16 = { 0x03b1, 0x03b2, 0x03b3, 0x00 },
	.utf16_size = 8,
	.utf8 = "\316\261\316\262\316\263",
};

static struct utf8_from_utf16_test utf8_from_utf16_test3 = {
	.utf16 = { 0x61, 0x62, 0xd801, 0x00 },
	.utf16_size = 8,
};

static struct utf8_from_utf16_test utf8_from_utf16_test4 = {
	.utf16 = { 0x61, 0x62, 0xdc01, 0x00 },
	.utf16_size = 8,
};

static void test_utf8_from_utf16(const void *test_data)
{
	const struct utf8_from_utf16_test *test = test_data;
	char *utf8;

	utf8 = l_utf8_from_utf16(test->utf16, test->utf16_size);

	if (test->utf8) {
		assert(utf8);
		assert(!strcmp(utf8, test->utf8));
		l_free(utf8);
	} else
		assert(!utf8);
}

static void test_utf8_to_utf16(const void *test_data)
{
	const struct utf8_from_utf16_test *test = test_data;
	void *utf16;
	size_t size;

	utf16 = l_utf8_to_utf16(test->utf8, &size);
	assert(utf16);
	assert(size == test->utf16_size);
	assert(!memcmp(utf16, test->utf16, size));

	l_free(utf16);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("Validate UTF 1", test_utf8_validate,
					&utf8_validate_test1);
	l_test_add("Validate UTF 2", test_utf8_validate,
					&utf8_validate_test2);
	l_test_add("Validate UTF 3", test_utf8_validate,
					&utf8_validate_test3);
	l_test_add("Validate UTF 4", test_utf8_validate,
					&utf8_validate_test4);
	l_test_add("Validate UTF 5", test_utf8_validate,
					&utf8_validate_test5);
	l_test_add("Validate UTF 6", test_utf8_validate,
					&utf8_validate_test6);
	l_test_add("Validate UTF 7", test_utf8_validate,
					&utf8_validate_test7);
	l_test_add("Validate UTF 8", test_utf8_validate,
					&utf8_validate_test8);
	l_test_add("Validate UTF 9", test_utf8_validate,
					&utf8_validate_test9);
	l_test_add("Validate UTF 10", test_utf8_validate,
					&utf8_validate_test10);
	l_test_add("Validate UTF 11", test_utf8_validate,
					&utf8_validate_test11);
	l_test_add("Validate UTF 12", test_utf8_validate,
					&utf8_validate_test12);
	l_test_add("Validate UTF 13", test_utf8_validate,
					&utf8_validate_test13);
	l_test_add("Validate UTF 14", test_utf8_validate,
					&utf8_validate_test14);
	l_test_add("Validate UTF 15", test_utf8_validate,
					&utf8_validate_test15);
	l_test_add("Validate UTF 16", test_utf8_validate,
					&utf8_validate_test16);
	l_test_add("Validate UTF 17", test_utf8_validate,
					&utf8_validate_test17);
	l_test_add("Validate UTF 18", test_utf8_validate,
					&utf8_validate_test18);
	l_test_add("Validate UTF 19", test_utf8_validate,
					&utf8_validate_test19);
	l_test_add("Validate UTF 20", test_utf8_validate,
					&utf8_validate_test20);
	l_test_add("Validate UTF 21", test_utf8_validate,
					&utf8_validate_test21);
	l_test_add("Validate UTF 22", test_utf8_validate,
					&utf8_validate_test22);
	l_test_add("Validate UTF 23", test_utf8_validate,
					&utf8_validate_test23);
	l_test_add("Validate UTF 24", test_utf8_validate,
					&utf8_validate_test24);
	l_test_add("Validate UTF 25", test_utf8_validate,
					&utf8_validate_test25);
	l_test_add("Validate UTF 26", test_utf8_validate,
					&utf8_validate_test26);
	l_test_add("Validate UTF 27", test_utf8_validate,
					&utf8_validate_test27);
	l_test_add("Validate UTF 28", test_utf8_validate,
					&utf8_validate_test28);
	l_test_add("Validate UTF 29", test_utf8_validate,
					&utf8_validate_test29);
	l_test_add("Validate UTF 30", test_utf8_validate,
					&utf8_validate_test30);
	l_test_add("Validate UTF 31", test_utf8_validate,
					&utf8_validate_test31);
	l_test_add("Validate UTF 32", test_utf8_validate,
					&utf8_validate_test32);
	l_test_add("Validate UTF 33", test_utf8_validate,
					&utf8_validate_test33);
	l_test_add("Validate UTF 34", test_utf8_validate,
					&utf8_validate_test34);
	l_test_add("Validate UTF 35", test_utf8_validate,
					&utf8_validate_test35);
	l_test_add("Validate UTF 36", test_utf8_validate,
					&utf8_validate_test36);
	l_test_add("Validate UTF 37", test_utf8_validate,
					&utf8_validate_test37);
	l_test_add("Validate UTF 38", test_utf8_validate,
					&utf8_validate_test38);
	l_test_add("Validate UTF 39", test_utf8_validate,
					&utf8_validate_test39);
	l_test_add("Validate UTF 40", test_utf8_validate,
					&utf8_validate_test40);
	l_test_add("Validate UTF 41", test_utf8_validate,
					&utf8_validate_test41);
	l_test_add("Validate UTF 42", test_utf8_validate,
					&utf8_validate_test42);
	l_test_add("Validate UTF 43", test_utf8_validate,
					&utf8_validate_test43);
	l_test_add("Validate UTF 44", test_utf8_validate,
					&utf8_validate_test44);
	l_test_add("Validate UTF 45", test_utf8_validate,
					&utf8_validate_test45);
	l_test_add("Validate UTF 46", test_utf8_validate,
					&utf8_validate_test46);
	l_test_add("Validate UTF 47", test_utf8_validate,
					&utf8_validate_test47);
	l_test_add("Validate UTF 48", test_utf8_validate,
					&utf8_validate_test48);
	l_test_add("Validate UTF 49", test_utf8_validate,
					&utf8_validate_test49);
	l_test_add("Validate UTF 50", test_utf8_validate,
					&utf8_validate_test50);
	l_test_add("Validate UTF 51", test_utf8_validate,
					&utf8_validate_test51);
	l_test_add("Validate UTF 52", test_utf8_validate,
					&utf8_validate_test52);
	l_test_add("Validate UTF 53", test_utf8_validate,
					&utf8_validate_test53);
	l_test_add("Validate UTF 54", test_utf8_validate,
					&utf8_validate_test54);
	l_test_add("Validate UTF 55", test_utf8_validate,
					&utf8_validate_test55);
	l_test_add("Validate UTF 56", test_utf8_validate,
					&utf8_validate_test56);
	l_test_add("Validate UTF 57", test_utf8_validate,
					&utf8_validate_test57);
	l_test_add("Validate UTF 58", test_utf8_validate,
					&utf8_validate_test58);
	l_test_add("Validate UTF 59", test_utf8_validate,
					&utf8_validate_test59);
	l_test_add("Validate UTF 60", test_utf8_validate,
					&utf8_validate_test60);
	l_test_add("Validate UTF 61", test_utf8_validate,
					&utf8_validate_test61);
	l_test_add("Validate UTF 62", test_utf8_validate,
					&utf8_validate_test62);
	l_test_add("Validate UTF 63", test_utf8_validate,
					&utf8_validate_test63);
	l_test_add("Validate UTF 64", test_utf8_validate,
					&utf8_validate_test64);
	l_test_add("Validate UTF 65", test_utf8_validate,
					&utf8_validate_test65);
	l_test_add("Validate UTF 66", test_utf8_validate,
					&utf8_validate_test66);
	l_test_add("Validate UTF 67", test_utf8_validate,
					&utf8_validate_test67);
	l_test_add("Validate UTF 68", test_utf8_validate,
					&utf8_validate_test68);
	l_test_add("Validate UTF 69", test_utf8_validate,
					&utf8_validate_test69);
	l_test_add("Validate UTF 70", test_utf8_validate,
					&utf8_validate_test70);
	l_test_add("Validate UTF 71", test_utf8_validate,
					&utf8_validate_test71);
	l_test_add("Validate UTF 72", test_utf8_validate,
					&utf8_validate_test72);
	l_test_add("Validate UTF 73", test_utf8_validate,
					&utf8_validate_test73);
	l_test_add("Validate UTF 74", test_utf8_validate,
					&utf8_validate_test74);
	l_test_add("Validate UTF 75", test_utf8_validate,
					&utf8_validate_test75);
	l_test_add("Validate UTF 76", test_utf8_validate,
					&utf8_validate_test76);
	l_test_add("Validate UTF 77", test_utf8_validate,
					&utf8_validate_test77);
	l_test_add("Validate UTF 78", test_utf8_validate,
					&utf8_validate_test78);
	l_test_add("Validate UTF 79", test_utf8_validate,
					&utf8_validate_test79);
	l_test_add("Validate UTF 80", test_utf8_validate,
					&utf8_validate_test80);

	l_test_add("Strlen UTF 1", test_utf8_strlen,
					&utf8_strlen_test1);

	l_test_add("utf8_from_utf16 1", test_utf8_from_utf16,
					&utf8_from_utf16_test1);
	l_test_add("utf8_from_utf16 2", test_utf8_from_utf16,
					&utf8_from_utf16_test2);
	l_test_add("utf8_from_utf16 3", test_utf8_from_utf16,
					&utf8_from_utf16_test3);
	l_test_add("utf8_from_utf16 4", test_utf8_from_utf16,
					&utf8_from_utf16_test4);

	l_test_add("utf8_to_utf16 1", test_utf8_to_utf16,
					&utf8_from_utf16_test1);
	l_test_add("utf8_to_utf16 2", test_utf8_to_utf16,
					&utf8_from_utf16_test2);

	return l_test_run();
}
