/*
 *  Embedded Linux library
 *
 *  Copyright (C) 2017  Intel Corporation. All rights reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>

#include <glib.h>
#include <ell/ell.h>

static GMainLoop *event_loop;

struct ell_event_source {
	GSource source;
	GPollFD pollfd;
};

static gboolean event_prepare(GSource *source, gint *timeout)
{
	int r = l_main_prepare();
	*timeout = r;

	return FALSE;
}

static gboolean event_check(GSource *source)
{
	l_main_iterate(0);
	return FALSE;
}

static GSourceFuncs event_funcs = {
	.prepare = event_prepare,
	.check = event_check,
};

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void oneshot_handler(void *user_data)
{
	l_info("One-shot");
}

static bool write_handler(struct l_io *io, void *user_data)
{
	int fd = l_io_get_fd(io);
	char *str = "Hello";
	ssize_t written;

	written = write(fd, str, strlen(str));

	l_info("%zd bytes written", written);

	return false;
}

static bool read_handler(struct l_io *io, void *user_data)
{
	int fd = l_io_get_fd(io);
	char str[32];
	ssize_t result;

	result = read(fd, str, sizeof(str));

	l_info("%zd bytes read", result);

	g_main_loop_quit(event_loop);

	return false;
}

static void disconnect_handler(struct l_io *io, void *user_data)
{
	l_info("disconnect");
}

int main(int argc, char **argv)
{
	struct l_io *io1, *io2;
	int fd[2];
	struct ell_event_source *source;

	l_log_set_stderr();
	l_debug_enable("*");
	l_debug("hello");

	l_main_init();
	event_loop = g_main_loop_new(NULL, FALSE);

	source = (struct ell_event_source *) g_source_new(&event_funcs,
					sizeof(struct ell_event_source));

	source->pollfd.fd = l_main_get_epoll_fd();
	source->pollfd.events = G_IO_IN | G_IO_HUP | G_IO_ERR;

	g_source_add_poll((GSource *)source, &source->pollfd);
	g_source_attach((GSource *) source,
					g_main_loop_get_context(event_loop));

	l_idle_oneshot(oneshot_handler, NULL, NULL);

	if (socketpair(PF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fd) < 0) {
		l_error("Failed to create socket pair");
		goto done;
	}

	io1 = l_io_new(fd[0]);
	l_io_set_close_on_destroy(io1, true);
	l_io_set_debug(io1, do_debug, "[IO-1] ", NULL);
	l_io_set_read_handler(io1, read_handler, NULL, NULL);
	l_io_set_disconnect_handler(io1, disconnect_handler, NULL, NULL);

	io2 = l_io_new(fd[1]);
	l_io_set_close_on_destroy(io2, true);
	l_io_set_debug(io2, do_debug, "[IO-2] ", NULL);
	l_io_set_write_handler(io2, write_handler, NULL, NULL);
	l_io_set_disconnect_handler(io2, disconnect_handler, NULL, NULL);

	g_main_loop_run(event_loop);

	l_io_destroy(io2);
	l_io_destroy(io1);

done:
	g_source_destroy((GSource *) source);
	g_main_loop_unref(event_loop);
	l_main_exit();

	return 0;
}
