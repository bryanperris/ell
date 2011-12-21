/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
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

#include <stdio.h>

#include "util.h"
#include "string.h"
#include "private.h"

/**
 * SECTION:string
 * @short_description: Growable string buffer
 *
 * Growable string buffer support
 */

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

	if (!string)
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
	size_t size = strlen(src);

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
	const char *nul = memchr(src, 0, max);

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

	va_start(args, format);
	l_string_append_vprintf(dest, format, args);
	va_end(args);
}
