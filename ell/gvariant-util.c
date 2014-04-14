/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2012  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License version 2.1 as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include "gvariant-private.h"

static const char *simple_types = "sogybnqiuxtdh";
static const char *variable_types = "sogav";
static const char *fixed_types = "bynqhiuxtd";

/* The alignment of a container type is equal to the largest alignment of
 * any potential child of that container. This means that, even if an array
 * of 32-bit integers is empty, it still must be aligned to the nearest
 * multiple of 4 bytes. It also means that the variant type (described below)
 * has an alignment of 8 (since it could potentially contain a value of any
 * other type and the maximum alignment is 8).
 */
static int get_basic_alignment(const char type)
{
	switch (type) {
	case 'b':
		return 1;
	case 'y':
		return 1;
	case 'n':
	case 'q':
		return 2;
	case 'i':
	case 'u':
		return 4;
	case 'x':
	case 't':
	case 'd':
		return 8;
	case 's':
	case 'g':
	case 'o':
		return 1;
	case 'h':
		return 4;
	case 'v':
		return 8;
	default:
		return 0;
	}
}

static int get_basic_fixed_size(const char type)
{
	switch (type) {
	case 'b':
		return 1;
	case 'y':
		return 1;
	case 'n':
	case 'q':
		return 2;
	case 'i':
	case 'u':
		return 4;
	case 'x':
	case 't':
	case 'd':
		return 8;
	case 'h':
		return 4;
	default:
		return 0;
	}
}

static const char *validate_next_type(const char *sig, int *out_alignment)
{
	char s = *sig;
	int alignment;

	if (s == '\0')
		return NULL;

	if (strchr(simple_types, s) || s == 'v') {
		*out_alignment = get_basic_alignment(s);
		return sig + 1;
	}

	switch (s) {
	case 'a':
		return validate_next_type(++sig, out_alignment);

	case '{':
		s = *++sig;

		/* Dictionary keys can only be simple types */
		if (!strchr(simple_types, s))
			return NULL;

		alignment = get_basic_alignment(s);

		sig = validate_next_type(sig + 1, out_alignment);

		if (!sig)
			return NULL;

		if (*sig != '}')
			return NULL;

		if (alignment > *out_alignment)
			*out_alignment = alignment;

		return sig + 1;

	case '(':
	{
		int max_alignment = 1, alignment;

		sig++;

		while (sig && *sig != ')') {
			sig = validate_next_type(sig, &alignment);

			if (alignment > max_alignment)
				max_alignment = alignment;
		}

		if (!sig)
			return NULL;

		if (*sig != ')')
			return NULL;

		*out_alignment = max_alignment;

		return sig + 1;
	}
	}

	return NULL;
}

bool _gvariant_valid_signature(const char *sig)
{
	const char *s = sig;
	int a;

	do {
		s = validate_next_type(s, &a);

		if (!s)
			return false;
	} while (*s);

	return true;
}

int _gvariant_get_alignment(const char *sig)
{
	int max_alignment = 1, alignment;
	const char *s = sig;

	/* 8 is the largest alignment possible, so quit if we reach it */
	while (*s && max_alignment != 8) {
		s = validate_next_type(s, &alignment);
		if (!s)
			return 0;

		if (alignment > max_alignment)
			max_alignment = alignment;
	}

	return max_alignment;
}

bool _gvariant_is_fixed_size(const char *sig)
{
	while (*sig != 0) {
		if (strchr(variable_types, sig[0]))
			return false;

		sig += 1;
	}

	return true;
}
