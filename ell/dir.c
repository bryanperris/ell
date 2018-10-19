/*
 *
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
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <unistd.h>
#include <dirent.h>
#include <sys/inotify.h>

#include "private.h"
#include "queue.h"
#include "io.h"
#include "dir.h"

struct l_dir_watch {
	struct watch_desc *desc;
	l_dir_watch_event_func_t function;
	void *user_data;
	l_dir_watch_destroy_func_t destroy;
};

struct watch_desc {
	int wd;
	char *pathname;
	struct l_queue *events;
	struct l_queue *callbacks;
};

struct watch_event {
	char *pathname;
	uint32_t mask;
};

static struct l_io *inotify_io = NULL;
static struct l_queue *watch_list = NULL;

static void free_event(void *user_data)
{
	struct watch_event *event = user_data;

	l_free(event->pathname);
	l_free(event);
}

static bool desc_match_wd(const void *a, const void *b)
{
	const struct watch_desc *desc = a;
	int wd = L_PTR_TO_INT(b);

	return (desc->wd == wd);
}

static bool desc_match_pathname(const void *a, const void *b)
{
	const struct watch_desc *desc = a;
	const char *pathname = b;

	return !strcmp(desc->pathname, pathname);
}

static bool event_match_pathname(const void *a, const void *b)
{
	const struct watch_event *event = a;
	const char *pathname = b;

	return !strcmp(event->pathname, pathname);
}

static void handle_callback(struct watch_desc *desc, const char *pathname,
						enum l_dir_watch_event event)
{
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(desc->callbacks); entry;
							entry = entry->next) {
		struct l_dir_watch *watch = entry->data;

		if (watch->function)
			watch->function(pathname, event, watch->user_data);
	}
}

static void process_event(struct watch_desc *desc, const char *pathname,
								uint32_t mask)
{
	struct watch_event *event;

	if (!pathname)
		return;

	if (mask & (IN_ACCESS | IN_MODIFY | IN_OPEN | IN_CREATE)) {
		event = l_queue_find(desc->events, event_match_pathname,
								pathname);
		if (!event) {
			/*
			 * When the event for a given pathname is not yet
			 * created and it is from type IN_MODIFY, then it
			 * might have been caused by a truncate() system
			 * call that does not open() the file. However
			 * treat this as modified as well.
			 */
			if (mask & IN_MODIFY) {
				handle_callback(desc, pathname,
						L_DIR_WATCH_EVENT_MODIFIED);
			} else {
				event = l_new(struct watch_event, 1);
				event->pathname = l_strdup(pathname);
				event->mask = mask;

				l_queue_push_tail(desc->events, event);
			}
		} else {
			event->mask |= mask;
		}
	} else if (mask & (IN_CLOSE_WRITE)) {
		event = l_queue_remove_if(desc->events, event_match_pathname,
								pathname);
		if (event) {
			/*
			 * Creation of a new file is treated differently,
			 * then modification, but for that the original
			 * system call needs to be looked at.
			 */
			if (event->mask & IN_CREATE)
				handle_callback(desc, pathname,
						L_DIR_WATCH_EVENT_CREATED);
			else
				handle_callback(desc, pathname,
						L_DIR_WATCH_EVENT_MODIFIED);

			free_event(event);
		} else {
			handle_callback(desc, pathname,
					L_DIR_WATCH_EVENT_MODIFIED);
		}
	} else if (mask & (IN_CLOSE_NOWRITE)) {
		event = l_queue_remove_if(desc->events, event_match_pathname,
								pathname);
		if (event) {
			if (event->mask & IN_ACCESS)
				handle_callback(desc, pathname,
						L_DIR_WATCH_EVENT_ACCESSED);
			free_event(event);
		}
	} else if (mask & (IN_MOVED_FROM | IN_DELETE)) {
		handle_callback(desc, pathname, L_DIR_WATCH_EVENT_REMOVED);
	} else if (mask & (IN_MOVED_TO)) {
		handle_callback(desc, pathname, L_DIR_WATCH_EVENT_CREATED);
	}
}

static bool inotify_read_cb(struct l_io *io, void *user_data)
{
	int fd = l_io_get_fd(io);
	uint8_t buf[sizeof(struct inotify_event) + NAME_MAX + 1]
		__attribute__ ((aligned(__alignof__(struct inotify_event))));
	const void *ptr = buf;
	ssize_t len;

	len = TEMP_FAILURE_RETRY(read(fd, buf, sizeof(buf)));
	if (len <= 0)
		return true;

	while (len > 0) {
		const struct inotify_event *event = ptr;
		const char *name = event->len ? event->name : NULL;
		struct watch_desc *desc;

		desc = l_queue_find(watch_list, desc_match_wd,
						L_INT_TO_PTR(event->wd));
		if (desc)
			process_event(desc, name, event->mask);

		ptr += sizeof(struct inotify_event) + event->len;
		len -= sizeof(struct inotify_event) + event->len;
	}

	return true;
}

static int setup_inotify(void)
{
	struct l_io *io;
	int fd;

	if (inotify_io)
		goto done;

	fd = inotify_init1(IN_CLOEXEC);
	if (fd < 0)
		return -1;

	io = l_io_new(fd);
	if (!io) {
		close(fd);
		return -1;
	}

	l_io_set_close_on_destroy(io, true);

	if (!l_io_set_read_handler(io, inotify_read_cb, NULL, NULL)) {
		l_io_destroy(io);
		return -1;
	}

	watch_list = l_queue_new();
	inotify_io = io;

done:
	return l_io_get_fd(inotify_io);
}

static void shutdown_inotify(void)
{
	if (!inotify_io)
		return;

	if (l_queue_isempty(watch_list)) {
		l_io_destroy(inotify_io);
		inotify_io = NULL;

		l_queue_destroy(watch_list, NULL);
		watch_list = NULL;
	}
}

LIB_EXPORT struct l_dir_watch *l_dir_watch_new(const char *pathname,
					l_dir_watch_event_func_t function,
					void *user_data,
					l_dir_watch_destroy_func_t destroy)
{
	struct l_dir_watch *watch;
	struct watch_desc *desc;
	int fd;

	if (!pathname)
		return NULL;

	watch = l_new(struct l_dir_watch, 1);
	watch->function = function;
	watch->user_data = user_data;
	watch->destroy = destroy;

	desc = l_queue_find(watch_list, desc_match_pathname, pathname);
	if (desc)
		goto done;

	/*
	 * Returns the inotify file descriptor. It will create a new one
	 * if it doesn't exist yet or return the already opened one.
	 */
	fd = setup_inotify();
	if (fd < 0) {
		l_free(watch);
		return NULL;
	}

	desc = l_new(struct watch_desc, 1);

	desc->wd = inotify_add_watch(fd, pathname, IN_ALL_EVENTS |
							IN_ONLYDIR |
							IN_DONT_FOLLOW |
							IN_EXCL_UNLINK);
	if (desc->wd < 0) {
		/*
		 * If the setup_inotify() created the inotify file descriptor,
		 * then this will close it. Otherwise it will do nothing.
		 */
		shutdown_inotify();
		l_free(desc);
		l_free(watch);
		return NULL;
	}

	desc->pathname = l_strdup(pathname);
	desc->events = l_queue_new();
	desc->callbacks = l_queue_new();

	l_queue_push_tail(watch_list, desc);

done:
	l_queue_push_tail(desc->callbacks, watch);
	watch->desc = desc;
	return watch;
}

LIB_EXPORT void l_dir_watch_destroy(struct l_dir_watch *watch)
{
	struct watch_desc *desc;
	int fd;

	if (!watch)
		return;

	desc = watch->desc;
	l_queue_remove(desc->callbacks, watch);

	/*
	 * As long as the watch descriptor has callbacks registered, it is
	 * still needed to be active.
	 */
	if (!l_queue_isempty(desc->callbacks))
		goto done;

	if (!l_queue_remove(watch_list, desc))
		goto done;

	fd = l_io_get_fd(inotify_io);
	inotify_rm_watch(fd, desc->wd);

	l_queue_destroy(desc->callbacks, NULL);
	l_queue_destroy(desc->events, free_event);
	l_free(desc->pathname);
	l_free(desc);

	/*
	 * When the number of watches goes to zero, then this will close
	 * the inotify file descriptor, otherwise it will do nothing.
	 */
	shutdown_inotify();

done:
	if (watch->destroy)
		watch->destroy(watch->user_data);

	l_free(watch);
}
