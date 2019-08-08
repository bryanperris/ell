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
#include <sys/types.h>
#include <sys/stat.h>

#include "time.h"
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

/**
 * l_path_find:
 * @basename: The basename of the file, e.g. "vi"
 * @path_str: A list of paths formatted like $PATH, e.g. from getenv
 * @mode: mode to check.  This is the same mode as would be fed to access()
 *
 * Attempts to find @basename in one of the directories listed in @path_str.
 * Only directories with absolute paths are used.
 *
 * Returns: A newly-allocated string with the full path of the resolved file
 * given by @basename.  E.g. /usr/bin/vi.  Or NULL if no file could be found
 * that matches the given @mode.
 */
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

/**
 * l_path_get_mtime:
 * @path: The path of the file
 *
 * Attempts find the modified time of file pointed to by @path.  If @path
 * is a symbolic link, then the link is followed.
 *
 * Returns: The number of microseconds (usec) since the Epoch or L_TIME_INVALID
 * if an error occurred.
 */
LIB_EXPORT uint64_t l_path_get_mtime(const char *path)
{
	struct stat sb;
	int ret;

	if (unlikely(path == NULL))
		return L_TIME_INVALID;

	ret = stat(path, &sb);
	if (ret < 0)
		return L_TIME_INVALID;

	return sb.st_mtim.tv_sec * 1000000 + sb.st_mtim.tv_nsec / 1000;
}

/**
 * l_path_touch:
 * @path: The path of the file
 *
 * Updates the modification and last_accessed time of the file given by @path
 * to the current time. If @path is a symbolic link, then the link is followed.
 *
 * Returns: 0 if the file times could be updated successfully and -errno
 * otherwise.
 */
LIB_EXPORT int l_path_touch(const char *path)
{
	if (unlikely(!path))
		return -EINVAL;

	if (utimensat(0, path, NULL, 0) == 0)
		return 0;

	return -errno;
}
