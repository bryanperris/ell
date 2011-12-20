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
 * l_signal:
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
 * l_signal_new:
 * @initial_length: Initial length of the groable string
 *
 * Create new growable string.
 *
 * Returns: a newly allocated #l_string object.
 **/
LIB_EXPORT struct l_string *l_string_new(size_t initial_length)
{
	struct l_string *ret;

	ret = l_new(struct l_string, 1);

	grow_string(ret, initial_length);
	ret->str[0] = '\0';

	return ret;
}

/**
 * l_string_free:
 * @str: growable string object
 * @free_array: internal string array
 *
 * Free the growable string object.  If @free_array is #true, then the internal
 * array will be freed and NULL will be returned.  Otherwise the internal
 * array will be returned to the caller.  The caller is responsible for freeing
 * it using l_free().
 *
 * Returns: @str's internal buffer or NULL
 **/
LIB_EXPORT char *l_string_free(struct l_string *str, bool free_array)
{
	char *array = str->str;

	l_free(str);

	if (free_array) {
		l_free(array);
		array = NULL;
	}

	return array;
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
