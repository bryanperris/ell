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

#include <stdio.h>
#include <wchar.h>

#include "util.h"
#include "string.h"
#include "private.h"

/**
 * SECTION:string
 * @short_description: Growable string buffer
 *
 * Growable string buffer support
 */

unsigned char l_ascii_table[256] = {
	[0x00 ... 0x08] = L_ASCII_CNTRL,
	[0x09 ... 0x0D] = L_ASCII_CNTRL | L_ASCII_SPACE,
	[0x0E ... 0x1F] = L_ASCII_CNTRL,
	[0x20]		= L_ASCII_PRINT | L_ASCII_SPACE,
	[0x21 ... 0x2F] = L_ASCII_PRINT | L_ASCII_PUNCT,
	[0x30 ... 0x39] = L_ASCII_DIGIT | L_ASCII_XDIGIT | L_ASCII_PRINT,
	[0x3A ... 0x40] = L_ASCII_PRINT | L_ASCII_PUNCT,
	[0x41 ... 0x46] = L_ASCII_PRINT | L_ASCII_XDIGIT | L_ASCII_UPPER,
	[0x47 ... 0x5A] = L_ASCII_PRINT | L_ASCII_UPPER,
	[0x5B ... 0x60] = L_ASCII_PRINT | L_ASCII_PUNCT,
	[0x61 ... 0x66] = L_ASCII_PRINT | L_ASCII_XDIGIT | L_ASCII_LOWER,
	[0x67 ... 0x7A] = L_ASCII_PRINT | L_ASCII_LOWER,
	[0x7B ... 0x7E] = L_ASCII_PRINT | L_ASCII_PUNCT,
	[0x7F]		= L_ASCII_CNTRL,
	[0x80 ... 0xFF] = 0,
};

/**
 * l_string:
 *
 * Opague object representing the string buffer.
 */
struct l_string {
	size_t max;
	size_t len;
	char *str;
};

static inline size_t next_power(size_t len)
{
	size_t n = 1;

	if (len > SIZE_MAX / 2)
		return SIZE_MAX;

	while (n < len)
		n = n << 1;

	return n;
}

static void grow_string(struct l_string *str, size_t extra)
{
	if (str->len + extra < str->max)
		return;

	str->max = next_power(str->len + extra + 1);
	str->str = l_realloc(str->str, str->max);
}

/**
 * l_string_new:
 * @initial_length: Initial length of the groable string
 *
 * Create new growable string.  If the @initial_length is 0, then a safe
 * default is chosen.
 *
 * Returns: a newly allocated #l_string object.
 **/
LIB_EXPORT struct l_string *l_string_new(size_t initial_length)
{
	static const size_t DEFAULT_INITIAL_LENGTH = 127;
	struct l_string *ret;

	ret = l_new(struct l_string, 1);

	if (initial_length == 0)
		initial_length = DEFAULT_INITIAL_LENGTH;

	grow_string(ret, initial_length);
	ret->str[0] = '\0';

	return ret;
}

/**
 * l_string_free:
 * @string: growable string object
 * @free_data: internal string array
 *
 * Free the growable string object.  If @free_data #true, then the internal
 * string data will be freed and NULL will be returned.  Otherwise the
 * internal string data will be returned to the caller.  The caller is
 * responsible for freeing it using l_free().
 *
 * Returns: @string's internal buffer or NULL
 **/
LIB_EXPORT char *l_string_free(struct l_string *string, bool free_data)
{
	char *result;

	if (unlikely(!string))
		return NULL;

	if (free_data) {
		l_free(string->str);
		result = NULL;
	} else
		result = string->str;

	l_free(string);

	return result;
}

/**
 * l_string_append:
 * @dest: growable string object
 * @src: C-style string to copy
 *
 * Appends the contents of @src to @dest.  The internal buffer of @dest is
 * grown if necessary.
 *
 * Returns: @dest
 **/
LIB_EXPORT struct l_string *l_string_append(struct l_string *dest,
						const char *src)
{
	size_t size;

	if (unlikely(!dest || !src))
		return NULL;

	size = strlen(src);

	grow_string(dest, size);

	memcpy(dest->str + dest->len, src, size);
	dest->len += size;
	dest->str[dest->len] = '\0';

	return dest;
}

/**
 * l_string_append_c:
 * @dest: growable string object
 * @c: Character
 *
 * Appends character given by @c to @dest.  The internal buffer of @dest is
 * grown if necessary.
 *
 * Returns: @dest
 **/
LIB_EXPORT struct l_string *l_string_append_c(struct l_string *dest,
						const char c)
{
	if (unlikely(!dest))
		return NULL;

	grow_string(dest, 1);
	dest->str[dest->len++] = c;
	dest->str[dest->len] = '\0';

	return dest;
}

/**
 * l_string_append_fixed:
 * @dest: growable string object
 * @src: Character array to copy from
 * @max: Maximum number of characters to copy
 *
 * Appends the contents of a fixed size string array @src to @dest.
 * The internal buffer of @dest is grown if necessary.  Up to a maximum of
 * @max characters are copied.  If a null is encountered in the first @max
 * characters, the string is copied only up to the NULL character.
 *
 * Returns: @dest
 **/
LIB_EXPORT struct l_string *l_string_append_fixed(struct l_string *dest,
							const char *src,
							size_t max)
{
	const char *nul;

	if (unlikely(!dest || !src || !max))
		return NULL;

	nul = memchr(src, 0, max);
	if (nul)
		max = nul - src;

	grow_string(dest, max);

	memcpy(dest->str + dest->len, src, max);
	dest->len += max;
	dest->str[dest->len] = '\0';

	return dest;
}

/**
 * l_string_append_vprintf:
 * @dest: growable string object
 * @format: the string format.  See the sprintf() documentation
 * @args: the parameters to insert
 *
 * Appends a formatted string to the growable string buffer.  This function
 * is equivalent to l_string_append_printf except that the arguments are
 * passed as a va_list.
 **/
LIB_EXPORT void l_string_append_vprintf(struct l_string *dest,
					const char *format, va_list args)
{
	size_t len;
	size_t have_space;
	va_list args_copy;

	if (unlikely(!dest))
		return;

	va_copy(args_copy, args);

	have_space = dest->max - dest->len;
	len = vsnprintf(dest->str + dest->len, have_space, format, args);

	if (len >= have_space) {
		grow_string(dest, len);
		len = vsprintf(dest->str + dest->len, format, args_copy);
	}

	dest->len += len;

	va_end(args_copy);
}

/**
 * l_string_append_printf:
 * @dest: growable string object
 * @format: the string format.  See the sprintf() documentation
 * @...: the parameters to insert
 *
 * Appends a formatted string to the growable string buffer, growing it as
 * necessary.
 **/
LIB_EXPORT void l_string_append_printf(struct l_string *dest,
					const char *format, ...)
{
	va_list args;

	if (unlikely(!dest))
		return;

	va_start(args, format);
	l_string_append_vprintf(dest, format, args);
	va_end(args);
}

/**
 * l_string_length:
 * @string: growable string object
 *
 * Returns: bytes used in the string.
 **/
LIB_EXPORT unsigned int l_string_length(struct l_string *string)
{
	if (unlikely(!string))
		return 0;

	return string->len;
}

static inline bool __attribute__ ((always_inline))
			valid_unicode(wchar_t c)
{
	if (c <= 0xd7ff)
		return true;

	if (c < 0xe000 || c > 0x10ffff)
		return false;

	if (c >= 0xfdd0 && c <= 0xfdef)
		return false;

	if ((c & 0xfffe) == 0xfffe)
		return false;

	return true;
}

/**
 * l_utf8_validate:
 * @str: a pointer to character data
 * @len: max bytes to validate
 * @end: return location for end of valid data
 *
 * Validates UTF-8 encoded text. If @end is non-NULL, then the end of
 * the valid range will be stored there (i.e. the start of the first
 * invalid character if some bytes were invalid, or the end of the text
 * being validated otherwise).
 *
 * Returns: Whether the text was valid UTF-8
 **/
LIB_EXPORT bool l_utf8_validate(const char *str, size_t len, const char **end)
{
	static const int mins[3] = { 1 << 7, 1 << 11, 1 << 16 };
	size_t pos = 0;
	unsigned int expect_bytes;
	wchar_t val;
	size_t i;

	while (pos < len && str[pos]) {
		if (str[pos] > 0) {
			pos += 1;
			continue;
		}

		expect_bytes = __builtin_clz(~(str[pos] << 24));

		if (expect_bytes < 2 || expect_bytes > 4)
			goto error;

		if (pos + expect_bytes > len)
			goto error;

		val = str[pos] & (0xff >> (expect_bytes + 1));

		for (i = pos + 1; i < pos + expect_bytes; i++) {
			if ((str[i] & 0xc0) == 0)
				goto error;

			val <<= 6;
			val |= str[i] & 0x3f;
		}

		if (val < mins[expect_bytes - 2])
			goto error;

		if (valid_unicode(val) == false)
			goto error;

		pos += expect_bytes;
	}

error:
	if (end)
		*end = str + pos;

	if (pos != len)
		return false;

	return true;
}

/**
 * l_utf8_strlen:
 * @str: a pointer to character data
 *
 * Computes the number of UTF-8 characters (not bytes) in the string given
 * by @str.
 *
 * Returns: The number of UTF-8 characters in the string
 **/
LIB_EXPORT size_t l_utf8_strlen(const char *str)
{
	size_t l = 0;
	size_t i;
	unsigned char b;

	for (i = 0; str[i]; i++) {
		b = str[i];

		if ((b >> 6) == 2)
			l += 1;
	}

	return i - l;
}
