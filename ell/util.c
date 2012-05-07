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
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>

#include "util.h"
#include "private.h"

/**
 * SECTION:util
 * @short_description: Utility functions
 *
 * Utility functions
 */

#define STRINGIFY(val) STRINGIFY_ARG(val)
#define STRINGIFY_ARG(contents) #contents

#define STRLOC __FILE__ ":" STRINGIFY(__LINE__)

/**
 * l_malloc:
 * @size: memory size to allocate
 *
 * If for any reason the memory allocation fails, then execution will be
 * halted via abort().
 *
 * In case @size is 0 then #NULL will be returned.
 *
 * Returns: pointer to allocated memory
 **/
LIB_EXPORT void *l_malloc(size_t size)
{
	if (likely(size)) {
		void *ptr;

		ptr = malloc(size);
		if (ptr)
			return ptr;

		fprintf(stderr, "%s:%s(): failed to allocate %zd bytes\n",
					STRLOC, __PRETTY_FUNCTION__, size);
		abort();
	}

	return NULL;
}

/**
 * l_realloc:
 * @mem: previously allocated memory, or NULL
 * @size: memory size to allocate
 *
 * If for any reason the memory allocation fails, then execution will be
 * halted via abort().
 *
 * In case @mem is NULL, this function acts like l_malloc.
 * In case @size is 0 then #NULL will be returned.
 *
 * Returns: pointer to allocated memory
 **/
LIB_EXPORT void *l_realloc(void *mem, size_t size)
{
	if (likely(size)) {
		void *ptr;

		ptr = realloc(mem, size);
		if (ptr)
			return ptr;

		fprintf(stderr, "%s:%s(): failed to re-allocate %zd bytes\n",
					STRLOC, __PRETTY_FUNCTION__, size);
		abort();
	} else
		l_free(mem);

	return NULL;
}

/**
 * l_free:
 * @ptr: memory pointer
 *
 * Free the allocated memory area.
 **/
LIB_EXPORT void l_free(void *ptr)
{
	free(ptr);
}

/**
 * l_strdup:
 * @str: string pointer
 *
 * Allocates and duplicates sring
 *
 * Returns: a newly allocated string
 **/
LIB_EXPORT char *l_strdup(const char *str)
{
	if (likely(str)) {
		char *tmp;

		tmp = strdup(str);
		if (tmp)
			return tmp;

		fprintf(stderr, "%s:%s(): failed to allocate string\n",
						STRLOC, __PRETTY_FUNCTION__);
		abort();
	}

	return NULL;
}

/**
 * l_strndup:
 * @str: string pointer
 *
 * Allocates and duplicates sring.  If the string is longer than @max
 * characters, only @max are copied and a null terminating character
 * is added.
 *
 * Returns: a newly allocated string
 **/
LIB_EXPORT char *l_strndup(const char *str, size_t max)
{
	if (likely(str)) {
		char *tmp;

		tmp = strndup(str, max);
		if (tmp)
			return tmp;

		fprintf(stderr, "%s:%s(): failed to allocate string\n",
						STRLOC, __PRETTY_FUNCTION__);
		abort();
	}

	return NULL;
}
/**
 * l_strdup_printf:
 * @format: string format
 * @...: parameters to insert into format string
 *
 * Returns: a newly allocated string
 **/
LIB_EXPORT char *l_strdup_printf(const char *format, ...)
{
	va_list args;
	char *str;
	int len;

	va_start(args, format);
	len = vasprintf(&str, format, args);
	va_end(args);

	if (len < 0) {
		fprintf(stderr, "%s:%s(): failed to allocate string\n",
					STRLOC, __PRETTY_FUNCTION__);
		abort();

		return NULL;
	}

	return str;
}

/**
 * l_util_hexstring:
 * @buf: buffer pointer
 * @len: length of buffer
 *
 * Returns: a newly allocated hex string
 **/
LIB_EXPORT char *l_util_hexstring(const unsigned char *buf, size_t len)
{
	static const char hexdigits[] = "0123456789abcdef";
	char *str;
	size_t i;

	if (unlikely(!buf) || unlikely(!len))
		return NULL;

	str = l_malloc(len * 2 + 1);

	for (i = 0; i < len; i++) {
		str[(i * 2) + 0] = hexdigits[buf[i] >> 4];
		str[(i * 2) + 1] = hexdigits[buf[i] & 0xf];
	}

	str[len * 2] = '\0';

	return str;
}

static void hexdump(const char dir, const unsigned char *buf, size_t len,
			l_util_hexdump_func_t function, void *user_data)
{
	static const char hexdigits[] = "0123456789abcdef";
	char str[68];
	size_t i;

	if (unlikely(!len))
		return;

	str[0] = dir;

	for (i = 0; i < len; i++) {
		str[((i % 16) * 3) + 1] = ' ';
		str[((i % 16) * 3) + 2] = hexdigits[buf[i] >> 4];
		str[((i % 16) * 3) + 3] = hexdigits[buf[i] & 0xf];
		str[(i % 16) + 51] = isprint(buf[i]) ? buf[i] : '.';

		if ((i + 1) % 16 == 0) {
			str[49] = ' ';
			str[50] = ' ';
			str[67] = '\0';
			function(str, user_data);
			str[0] = ' ';
		}
	}

	if (i % 16 > 0) {
		size_t j;
		for (j = (i % 16); j < 16; j++) {
			str[(j * 3) + 1] = ' ';
			str[(j * 3) + 2] = ' ';
			str[(j * 3) + 3] = ' ';
			str[j + 51] = ' ';
		}
		str[49] = ' ';
		str[50] = ' ';
		str[67] = '\0';
		function(str, user_data);
	}
}

LIB_EXPORT void l_util_hexdump(bool in, const void *buf, size_t len,
			l_util_hexdump_func_t function, void *user_data)
{
	if (likely(!function))
		return;

	hexdump(in ? '<' : '>', buf, len, function, user_data);
}

LIB_EXPORT void l_util_hexdump_two(bool in, const void *buf1, size_t len1,
			const void *buf2, size_t len2,
			l_util_hexdump_func_t function, void *user_data)
{
	if (likely(!function))
		return;

	hexdump(in ? '<' : '>', buf1, len1, function, user_data);
	hexdump(' ', buf2, len2, function, user_data);
}

LIB_EXPORT void l_util_debug(l_util_hexdump_func_t function, void *user_data,
						const char *format, ...)
{
	va_list args;
	char *str;
	int len;

	if (likely(!function))
		return;

	if (unlikely(!format))
		return;

	va_start(args, format);
	len = vasprintf(&str, format, args);
	va_end(args);

	if (unlikely(len < 0))
		return;

	function(str, user_data);

	free(str);
}
