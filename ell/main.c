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
#include <errno.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "util.h"
#include "main.h"
#include "hashmap.h"
#include "private.h"

#define MAX_EPOLL_EVENTS 10

static int epoll_fd;
static bool epoll_running;
static bool epoll_terminate;

static struct l_hashmap *watch_list;

struct watch_data {
	uint32_t events;
	watch_event_cb_t callback;
	watch_destroy_cb_t destroy;
	void *user_data;
};

static inline bool create_epoll(void)
{
	if (epoll_fd)
		return true;

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd < 0) {
		epoll_fd = 0;
		return false;
	}

	watch_list = l_hashmap_new();
	if (!watch_list) {
		close(epoll_fd);
		epoll_fd = 0;
		return false;
	}

	return true;
}

int watch_add(int fd, uint32_t events, watch_event_cb_t callback,
				void *user_data, watch_destroy_cb_t destroy)
{
	struct watch_data *data;
	struct epoll_event ev;
	int err;

	if (fd < 0 || !callback)
		return -EINVAL;

	if (!create_epoll())
		return -EIO;

	data = l_new(struct watch_data, 1);

	data->events = events;
	data->callback = callback;
	data->destroy = destroy;
	data->user_data = user_data;

	if (l_hashmap_insert(watch_list, L_INT_TO_PTR(fd), data) < 0) {
		l_free(data);
		return -ENOMEM;
	}

	memset(&ev, 0, sizeof(ev));
	ev.events = events;
	ev.data.fd = fd;

	err = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
	if (err < 0) {
		l_hashmap_remove(watch_list, L_INT_TO_PTR(fd));
		l_free(data);
		return err;
	}

	return 0;
}

int watch_modify(int fd, uint32_t events)
{
	struct watch_data *data;
	struct epoll_event ev;
	int err;

	if (fd < 0)
		return -EINVAL;

	data = l_hashmap_lookup(watch_list, L_INT_TO_PTR(fd));
	if (!data)
		return -ENXIO;

	if (data->events == events)
		return 0;

	memset(&ev, 0, sizeof(ev));
	ev.events = events;
	ev.data.fd = fd;

	err = epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
	if (err < 0)
		return err;

	data->events = events;

	return 0;
}

int watch_remove(int fd)
{
	struct watch_data *data;
	int err;

	if (fd < 0)
		return -EINVAL;

	data = l_hashmap_remove(watch_list, L_INT_TO_PTR(fd));
	if (!data)
		return -ENXIO;

	err = epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);

	if (data->destroy)
		data->destroy(data->user_data);

	l_free(data);

	return err;
}

static void watch_destroy(const void *key, void *value)
{
	int fd = L_PTR_TO_INT(key);

	fprintf(stderr, "Dangling file descriptor %d found", fd);
}

LIB_EXPORT bool l_main_run(void)
{
	if (epoll_running)
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
			struct watch_data *data;
			int fd = events[n].data.fd;

			data = l_hashmap_lookup(watch_list, L_INT_TO_PTR(fd));
			if (!data)
				continue;

			if (!data->callback)
				continue;

			data->callback(fd, events[n].events, data->user_data);
		}
	}

	l_hashmap_destroy(watch_list, watch_destroy);
	watch_list = NULL;

	epoll_running = false;

	close(epoll_fd);
	epoll_fd = 0;

	return true;
}

LIB_EXPORT bool l_main_quit(void)
{
	if (!epoll_running)
		return false;

	epoll_terminate = true;

	return true;
}
