/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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

#define _GNU_SOURCE
#include <unistd.h>

#include "path.h"
#include "private.h"

static const char *next_in_path(const char *path, char **ret, size_t overhead)
{
	const char *p = path;
	char *r;
	size_t toalloc = 0;

	while (p[0] != '\0' && p[0] != ':') {
		switch (*p) {
		case '\\':
			if (!*++p)
				break;
			/* Fall through */
		default:
			p++;
			toalloc += 1;
			break;
		}
	}

	r = l_new(char, toalloc + 1 + overhead);
	p = path;
	*ret = r;

	while (p[0] != '\0' && p[0] != ':') {
		switch (*p) {
		case '\\':
			if (!*++p)
				break;
			/* Fall through */
		default:
			*r++ = *p++;
			break;
		}
	}

	if (p[0] == ':')
		p++;

	return p;
}

/**
 * l_path_next:
 * @path_str: contents of $PATH-like string
 * @ret: The returned value
 *
 * Attempts to parse the next element of a $PATH-like string and returns the
 * resulting directory in a newly-allocated variable assigned to @ret.  @ret
 * must be a valid pointer to a char *.
 *
 * Returns: A pointer inside @path_str that begins just past the next ':'
 * delimiter character or to the end of the string.
 **/
LIB_EXPORT const char *l_path_next(const char *path_str, char **ret)
{
	if (unlikely(!path_str))
		return NULL;

	return next_in_path(path_str, ret, 0);
}

LIB_EXPORT char *l_path_find(const char *basename,
					const char *path_str, int mode)
{
	size_t overhead;
	size_t len;
	char *path;

	if (unlikely(!path_str || !basename))
		return NULL;

	overhead = strlen(basename) + 1;

	do {
		path_str = next_in_path(path_str, &path, overhead);

		if (path[0] == '/') {
			len = strlen(path);

			if (path[len - 1] != '/')
				path[len++] = '/';

			strcpy(path + len, basename);

			if (access(path, mode) == 0)
				return path;
		}

		l_free(path);
	} while (path_str[0] != '\0');

	return NULL;
}
