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

#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "util.h"
#include "io.h"
#include "private.h"

/**
 * SECTION:io
 * @short_description: IO support
 *
 * IO support
 */

/**
 * l_io:
 *
 * Opague object representing the IO.
 */
struct l_io {
	int fd;
	uint32_t events;
	bool close_on_destroy;
	l_io_read_cb_t read_handler;
	l_io_destroy_cb_t read_destroy;
	void *read_data;
	l_io_write_cb_t write_handler;
	l_io_destroy_cb_t write_destroy;
	void *write_data;
	l_io_debug_cb_t debug_handler;
	l_io_destroy_cb_t debug_destroy;
	void *debug_data;
};

static inline void __attribute__ ((always_inline))
			debug(struct l_io *io, const char *message)
{
	if (!io->debug_handler)
		return;

	io->debug_handler(message, io->debug_data);
}

static void io_cleanup(void *user_data)
{
	struct l_io *io = user_data;

	debug(io, "cleanup");

	if (io->write_destroy)
		io->write_destroy(io->write_data);

	if (io->read_destroy)
		io->read_destroy(io->read_data);

	if (io->debug_destroy)
		io->debug_destroy(io->debug_data);

	if (io->close_on_destroy)
		close(io->fd);

	l_free(io);
}

static void io_callback(int fd, uint32_t events, void *user_data)
{
	struct l_io *io = user_data;

	if ((events & EPOLLIN) && io->read_handler) {
		debug(io, "read event");

		io->read_handler(io, io->read_data);
	}

	if ((events & EPOLLOUT) && io->write_handler) {
		debug(io, "write event");

		if (!io->write_handler(io, io->write_data)) {
			if (io->write_destroy)
				io->write_destroy(io->write_data);

			io->write_handler = NULL;
			io->write_destroy = NULL;
			io->write_data = NULL;

			io->events &= ~EPOLLOUT;

			watch_modify(io->fd, io->events);
		}
	}
}

/**
 * l_io_new:
 * @fd: file descriptor
 *
 * Create new IO handling for a given file descriptor.
 *
 * Returns: a newly allocated #l_io object
 **/
LIB_EXPORT struct l_io *l_io_new(int fd)
{
	struct l_io *io;

	io = l_new(struct l_io, 1);

	io->fd = fd;
	io->events = 0;
	io->close_on_destroy = false;

	watch_add(io->fd, io->events, io_callback, io, io_cleanup);

	return io;
}

/**
 * l_io_destroy:
 * @io: IO object
 *
 * Free IO object and close file descriptor (if enabled).
 **/
LIB_EXPORT void l_io_destroy(struct l_io *io)
{
	if (!io)
		return;

	watch_remove(io->fd);
}

/**
 * l_io_get_fd:
 * @io: IO object
 *
 * Returns: file descriptor associated with @io
 **/
LIB_EXPORT int l_io_get_fd(struct l_io *io)
{
	if (!io)
		return -1;

	return io->fd;
}

/**
 * l_io_set_close_on_destroy:
 * @io: IO object
 * @do_close: setting for destroy handling
 *
 * Set the automatic closing of the file descriptor when destroying @io.
 *
 * Returns: #true on success and #false on failure
 **/
LIB_EXPORT bool l_io_set_close_on_destroy(struct l_io *io, bool do_close)
{
	if (!io)
		return false;

	io->close_on_destroy = do_close;

	return true;
}

/**
 * l_io_set_read_handler:
 * @io: IO object
 * @callback: read handler callback function
 * @user_data: user data provided to read handler callback function
 * @destroy: destroy function for user data
 *
 * Set read function.
 *
 * Returns: #true on success and #false on failure
 **/
LIB_EXPORT bool l_io_set_read_handler(struct l_io *io, l_io_read_cb_t callback,
				void *user_data, l_io_destroy_cb_t destroy)
{
	uint32_t events;

	if (!io || io->fd < 0)
		return false;

	debug(io, "set read handler");

	if (io->read_destroy)
		io->read_destroy(io->read_data);

	if (callback)
		events = io->events | EPOLLIN;
	else
		events = io->events & ~EPOLLIN;

	io->read_handler = callback;
	io->read_destroy = destroy;
	io->read_data = user_data;

	if (events == io->events)
		return true;

	watch_modify(io->fd, events);

	io->events = events;

	return true;
}

/**
 * l_io_set_write_handler:
 * @io: IO object
 * @callback: write handler callback function
 * @user_data: user data provided to write handler callback function
 * @destroy: destroy function for user data
 *
 * Set write function.
 *
 * Returns: #true on success and #false on failure
 **/
LIB_EXPORT bool l_io_set_write_handler(struct l_io *io, l_io_write_cb_t callback,
				void *user_data, l_io_destroy_cb_t destroy)
{
	uint32_t events;

	if (!io || io->fd < 0)
		return false;

	debug(io, "set write handler");

	if (io->write_handler == callback && io->write_destroy == destroy &&
						io->write_data == user_data)
		return true;

	if (io->write_destroy)
		io->write_destroy(io->write_data);

	if (callback)
		events = io->events | EPOLLOUT;
	else
		events = io->events & ~EPOLLOUT;

	io->write_handler = callback;
	io->write_destroy = destroy;
	io->write_data = user_data;

	if (events == io->events)
		return true;

	watch_modify(io->fd, events);

	io->events = events;

	return true;
}

/**
 * l_io_set_debug:
 * @io: IO object
 * @callback: debug callback function
 * @user_data: user data provided to debug callback function
 * @destroy: destroy function for user data
 *
 * Set debug function.
 *
 * Returns: #true on success and #false on failure
 **/
LIB_EXPORT bool l_io_set_debug(struct l_io *io, l_io_debug_cb_t callback,
				void *user_data, l_io_destroy_cb_t destroy)
{
	if (!io)
		return false;

	if (io->debug_destroy)
		io->debug_destroy(io->debug_data);

	io->debug_handler = callback;
	io->debug_destroy = destroy;
	io->debug_data = user_data;

	return true;
}
