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

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "util.h"
#include "hwdb.h"
#include "private.h"

struct l_hwdb {
	int ref_count;
	int fd;
	off_t size;
	void *addr;
};

LIB_EXPORT struct l_hwdb *l_hwdb_new(const char *pathname)
{
	struct l_hwdb *hwdb;
	struct stat st;
	void *addr;
	int fd;

	if (!pathname)
		return NULL;

	fd = open(pathname, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;

	if (fstat(fd, &st) < 0) {
		close(fd);
		return NULL;
	}

	addr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		close(fd);
		return NULL;
	}

	hwdb = l_new(struct l_hwdb, 1);

	hwdb->fd = fd;
	hwdb->size = st.st_size;
	hwdb->addr = addr;

	return l_hwdb_ref(hwdb);
}

LIB_EXPORT struct l_hwdb *l_hwdb_new_default(void)
{
	return l_hwdb_new("/etc/udev/hwdb.bin");
}

LIB_EXPORT struct l_hwdb *l_hwdb_ref(struct l_hwdb *hwdb)
{
	if (!hwdb)
		return NULL;

	__sync_fetch_and_add(&hwdb->ref_count, 1);

	return hwdb;
}

LIB_EXPORT void l_hwdb_unref(struct l_hwdb *hwdb)
{
	if (!hwdb)
		return;

	if (__sync_sub_and_fetch(&hwdb->ref_count, 1))
		return;

	munmap(hwdb->addr, hwdb->size);

	close(hwdb->fd);

	l_free(hwdb);
}
