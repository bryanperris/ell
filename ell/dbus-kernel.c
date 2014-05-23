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

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "linux/kdbus.h"

#include "dbus.h"
#include "dbus-private.h"

int _dbus_kernel_create_bus(const char *name)
{
	struct {
		struct kdbus_cmd_make head;
		/* bloom size item */
		uint64_t bloom_size;
		uint64_t bloom_type;
		struct kdbus_bloom_parameter bloom_param;
		/* name item */
		uint64_t name_size;
		uint64_t name_type;
		char name_param[64];
	} bus_make;
	int fd;

	fd = open("/dev/kdbus/control", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return -1;

	memset(&bus_make, 0, sizeof(bus_make));
	/* bloom size item */
	bus_make.bloom_size = 16 + sizeof(bus_make.bloom_param);
	bus_make.bloom_type = KDBUS_ITEM_BLOOM_PARAMETER;
	bus_make.bloom_param.size = 64;
	bus_make.bloom_param.n_hash = 1;
	/* name item */
	snprintf(bus_make.name_param, sizeof(bus_make.name_param), "%s", name);
	bus_make.name_size = 16 + strlen(bus_make.name_param) + 1;
	bus_make.name_type = KDBUS_ITEM_MAKE_NAME;
	/* bus make head */
	bus_make.head.size = sizeof(bus_make.head) +
				bus_make.bloom_size + bus_make.name_size;
	bus_make.head.flags = KDBUS_MAKE_ACCESS_WORLD;

	if (ioctl(fd, KDBUS_CMD_BUS_MAKE, &bus_make) < 0) {
		close(fd);
		return -1;
        }

	return fd;
}
