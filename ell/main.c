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

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/epoll.h>

#include "log.h"
#include "util.h"
#include "main.h"
#include "private.h"

/**
 * SECTION:main
 * @short_description: Main loop handling
 *
 * Main loop handling
 */

#define MAX_EPOLL_EVENTS 10

static int epoll_fd;
static bool epoll_running;
static bool epoll_terminate;

struct watch_data {
	int fd;
	uint32_t events;
	watch_event_cb_t callback;
	watch_destroy_cb_t destroy;
	void *user_data;
};

#define DEFAULT_WATCH_ENTRIES 128

static unsigned int watch_entries;
static struct watch_data **watch_list;

static inline bool __attribute__ ((always_inline)) create_epoll(void)
{
	unsigned int i;

	if (likely(epoll_fd))
		return true;

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0) {
		epoll_fd = 0;
		return false;
	}

	watch_list = malloc(DEFAULT_WATCH_ENTRIES * sizeof(void *));
	if (!watch_list) {
		close(epoll_fd);
		epoll_fd = 0;
		return false;
	}

	watch_entries = DEFAULT_WATCH_ENTRIES;

	for (i = 0; i < watch_entries; i++)
		watch_list[i] = NULL;

	return true;
}

int watch_add(int fd, uint32_t events, watch_event_cb_t callback,
				void *user_data, watch_destroy_cb_t destroy)
{
	struct watch_data *data;
	struct epoll_event ev;
	int err;

	if (unlikely(fd <= 0 || !callback))
		return -EINVAL;

	if (!create_epoll())
		return -EIO;

	if ((unsigned int) fd > watch_entries)
		return -ERANGE;

	data = l_new(struct watch_data, 1);

	data->fd = fd;
	data->events = events;
	data->callback = callback;
	data->destroy = destroy;
	data->user_data = user_data;

	memset(&ev, 0, sizeof(ev));
	ev.events = events;
	ev.data.ptr = data;

	err = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, data->fd, &ev);
	if (err < 0) {
		l_free(data);
		return err;
	}

	watch_list[fd - 1] = data;

	return 0;
}

int watch_modify(int fd, uint32_t events)
{
	struct watch_data *data;
	struct epoll_event ev;
	int err;

	if (unlikely(fd <= 0))
		return -EINVAL;

	if ((unsigned int) fd > watch_entries)
		return -ERANGE;

	data = watch_list[fd - 1];
	if (!data)
		return -ENXIO;

	if (data->events == events)
		return 0;

	memset(&ev, 0, sizeof(ev));
	ev.events = events;
	ev.data.ptr = data;

	err = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, data->fd, &ev);
	if (err < 0)
		return err;

	data->events = events;

	return 0;
}

int watch_remove(int fd)
{
	struct watch_data *data;
	int err;

	if (unlikely(fd <= 0))
		return -EINVAL;

	if ((unsigned int) fd > watch_entries)
		return -ERANGE;

	data = watch_list[fd - 1];
	if (!data)
		return -ENXIO;

	watch_list[fd - 1] = NULL;

	err = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, data->fd, NULL);

	if (data->destroy)
		data->destroy(data->user_data);

	l_free(data);

	return err;
}

/**
 * l_main_run:
 *
 * Run the main loop
 *
 * Returns: #true after successful execution or #false in case of failure
 **/
LIB_EXPORT bool l_main_run(void)
{
	unsigned int i;

	if (unlikely(epoll_running))
		return false;

	if (!create_epoll())
		return false;

	epoll_terminate = false;

	epoll_running = true;

	for (;;) {
		struct epoll_event events[MAX_EPOLL_EVENTS];
		int n, nfds;

		if (epoll_terminate)
			break;

		nfds = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, -1);
		if (nfds < 0)
			continue;

		for (n = 0; n < nfds; n++) {
			struct watch_data *data = events[n].data.ptr;

			data->callback(data->fd, events[n].events,
							data->user_data);
		}
	}

	for (i = 0; i < watch_entries; i++) {
		struct watch_data *data = watch_list[i];

		if (!data)
			continue;

		l_error("Dangling file descriptor %d found", data->fd);

		if (data->destroy)
			data->destroy(data->user_data);

		l_free(data);
	}

	watch_entries = 0;

	free(watch_list);
	watch_list = NULL;

	epoll_running = false;

	close(epoll_fd);
	epoll_fd = 0;

	return true;
}

/**
 * l_main_quit:
 *
 * Teminate the running main loop
 *
 * Returns: #true when terminating the main loop or #false in case of failure
 **/
LIB_EXPORT bool l_main_quit(void)
{
	if (unlikely(!epoll_running))
		return false;

	epoll_terminate = true;

	return true;
}
