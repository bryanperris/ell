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
#include <fcntl.h>
#include <unistd.h>

#include <ell/ell.h>

static void read_handler(struct l_io *io, void *user_data)
{
	int fd = l_io_get_fd(io);
	unsigned char buf[32];
	ssize_t result;

	result = read(fd, buf, sizeof(buf));
	if (result < 0)
		return;

	l_main_quit();
}

static void timeout_handler(struct l_timeout *timeout, void *user_data)
{
	l_main_quit();
}

int main(int argc, char *argv[])
{
	struct l_io *io;
	int fd;

	fd = open("/dev/rfkill", O_RDONLY);
	if (fd < 0)
		return 0;

	io = l_io_new(fd);
	if (!io)
		return 0;

	l_io_set_close_on_destroy(io, true);

	l_io_set_read_handler(io, read_handler, NULL, NULL);

	l_timeout_create(10, timeout_handler, NULL, NULL);

	l_main_run();

	return 0;
}
