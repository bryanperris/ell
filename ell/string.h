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

#ifndef __ELL_STRING_H
#define __ELL_STRING_H

#include <stdbool.h>
#include <stdarg.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

struct l_string;

extern unsigned char l_ascii_table[];

enum l_ascii {
	L_ASCII_CNTRL	= 0x80,
	L_ASCII_PRINT	= 0x40,
	L_ASCII_PUNCT	= 0x20,
	L_ASCII_SPACE	= 0x10,
	L_ASCII_XDIGIT	= 0x08,
	L_ASCII_UPPER	= 0x04,
	L_ASCII_LOWER	= 0x02,
	L_ASCII_DIGIT	= 0x01,
	L_ASCII_ALPHA	= L_ASCII_LOWER | L_ASCII_UPPER,
	L_ASCII_ALNUM	= L_ASCII_ALPHA | L_ASCII_DIGIT,
	L_ASCII_GRAPH	= L_ASCII_ALNUM | L_ASCII_PUNCT,
};

#define l_ascii_isalnum(c) \
	((l_ascii_table[(unsigned char) (c)] & L_ASCII_ALNUM) != 0)

#define l_ascii_isalpha(c) \
	((l_ascii_table[(unsigned char) (c)] & L_ASCII_ALPHA) != 0)

#define l_ascii_iscntrl(c) \
	((l_ascii_table[(unsigned char) (c)] & L_ASCII_CNTRL) != 0)

#define l_ascii_isdigit(c) \
	((l_ascii_table[(unsigned char) (c)] & L_ASCII_DIGIT) != 0)

#define l_ascii_isgraph(c) \
	((l_ascii_table[(unsigned char) (c)] & L_ASCII_GRAPH) != 0)

#define l_ascii_islower(c) \
	((l_ascii_table[(unsigned char) (c)] & L_ASCII_LOWER) != 0)

#define l_ascii_isprint(c) \
	((l_ascii_table[(unsigned char) (c)] & L_ASCII_PRINT) != 0)

#define l_ascii_ispunct(c) \
	((l_ascii_table[(unsigned char) (c)] & L_ASCII_PUNCT) != 0)

#define l_ascii_isspace(c) \
	((l_ascii_table[(unsigned char) (c)] & L_ASCII_SPACE) != 0)

#define l_ascii_isupper(c) \
	((l_ascii_table[(unsigned char) (c)] & L_ASCII_UPPER) != 0)

#define l_ascii_isxdigit(c) \
	((l_ascii_table[(unsigned char) (c)] & L_ASCII_XDIGIT) != 0)

static inline bool __attribute__ ((always_inline))
			l_ascii_isblank(unsigned char c)
{
	if (c == ' ' || c == '\t')
		return true;

	return false;
}

static inline bool __attribute__ ((always_inline))
			l_ascii_isascii(int c)
{
	if (c <= 127)
		return true;

	return false;
}

struct l_string *l_string_new(size_t initial_length);
void l_string_free(struct l_string *string);
char *l_string_unwrap(struct l_string *string);

struct l_string *l_string_append(struct l_string *dest, const char *src);
struct l_string *l_string_append_c(struct l_string *dest, const char c);
struct l_string *l_string_append_fixed(struct l_string *dest, const char *src,
					size_t max);

void l_string_append_vprintf(struct l_string *dest,
					const char *format, va_list args);
void l_string_append_printf(struct l_string *dest, const char *format, ...);

struct l_string *l_string_truncate(struct l_string *string, size_t new_size);

unsigned int l_string_length(struct l_string *string);

bool l_utf8_validate(const char *src, size_t len, const char **end);
int l_utf8_get_codepoint(const char *str, size_t len, wchar_t *cp);
size_t l_utf8_strlen(const char *src);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_STRING_H */
