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
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>

#include <ell/ell.h>

static void test_path_next(const void *data)
{
	char *path;
	const char *path_str;

	path_str = l_path_next("Foo:bar", &path);
	assert(path_str);
	assert(!strcmp(path, "Foo"));
	l_free(path);

	path_str = l_path_next(path_str, &path);
	assert(path_str);
	assert(*path_str == '\0');
	assert(!strcmp(path, "bar"));
	l_free(path);

	path_str = l_path_next("\"foo\\:::bar\\", &path);
	assert(path_str);
	assert(!strcmp(path, "\"foo:"));
	l_free(path);

	path_str = l_path_next(path_str, &path);
	assert(path_str);
	assert(!strcmp(path, ""));
	l_free(path);

	path_str = l_path_next(path_str, &path);
	assert(path_str);
	assert(!strcmp(path, "bar"));
	l_free(path);
}

static void test_path_find(const void *data)
{
	static const char *cant_find = "/foo:/bar:/dir:fr";
	static const char *can_find = "/tmp";
	char *tmp_path = l_strdup("/tmp/foobarXXXXXX.tmp");
	char *base;
	char *path;
	int fd;

	fd = L_TFR(mkostemps(tmp_path, 4, O_CLOEXEC));
	assert(fd > 0);
	L_TFR(close(fd));
	base = basename(tmp_path);

	assert(l_path_find(base, cant_find, F_OK) == NULL);

	path = l_path_find(base, can_find, F_OK);
	assert(path);
	assert(!strcmp(path, tmp_path));
	l_free(path);
	l_free(tmp_path);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("path/next", test_path_next, NULL);
	l_test_add("path/find", test_path_find, NULL);

	return l_test_run();
}
