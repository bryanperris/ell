/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#include <sys/inotify.h>

#include "private.h"
#include "util.h"
#include "io.h"
#include "queue.h"
#include "fswatch.h"

static struct l_io *inotify_io;
static struct l_queue *watches;
static bool in_notify;
static bool stale_items;

struct l_fswatch {
	int id;
	l_fswatch_cb_t cb;
	void *user_data;
	l_fswatch_destroy_cb_t destroy;
};

#define EVENT_MASK	(IN_CREATE | IN_DELETE | IN_DELETE_SELF | \
				IN_MODIFY | IN_MOVE | IN_MOVE_SELF | \
				IN_ATTRIB)

static void l_fswatch_free(void *data)
{
	struct l_fswatch *watch = data;

	if (watch->destroy)
		watch->destroy(watch->user_data);

	l_free(watch);
}

static void l_fswatch_shutdown(void)
{
	if (!inotify_io)
		return;

	l_io_destroy(inotify_io);
	inotify_io = NULL;
}

static bool l_fswatch_remove_func(const void *a, const void *b)
{
	const struct l_fswatch *watch = a;

	return !watch->cb;
}

static bool inotify_read_cb(struct l_io *io, void *user_data)
{
	uint8_t buf[sizeof(struct inotify_event) + NAME_MAX + 1]
		__attribute__ ((aligned(__alignof__(struct inotify_event))));
	const uint8_t *ptr;
	const struct inotify_event *event;
	ssize_t len;

	len = TEMP_FAILURE_RETRY(read(l_io_get_fd(io), buf, sizeof(buf)));
	if (unlikely(len <= 0))
		return true;

	in_notify = true;

	for (ptr = buf; ptr < buf + len;
			ptr += sizeof(struct inotify_event) + event->len) {
		const struct l_queue_entry *entry;
		const char *name = NULL;

		event = (struct inotify_event *) ptr;

		if (event->len)
			name = event->name;

		for (entry = l_queue_get_entries(watches); entry;
				entry = entry->next) {
			struct l_fswatch *watch = entry->data;

			if (watch->id != event->wd)
				continue;

			if ((event->mask & IN_CREATE) && watch->cb)
				watch->cb(watch, name, L_FSWATCH_EVENT_CREATE,
						watch->user_data);

			if ((event->mask & (IN_MOVE | IN_MOVE_SELF)) &&
					watch->cb)
				watch->cb(watch, name, L_FSWATCH_EVENT_MOVE,
						watch->user_data);

			if ((event->mask & IN_MODIFY) && watch->cb)
				watch->cb(watch, name, L_FSWATCH_EVENT_MODIFY,
						watch->user_data);

			if ((event->mask & (IN_DELETE | IN_DELETE_SELF)) &&
					watch->cb)
				watch->cb(watch, name, L_FSWATCH_EVENT_DELETE,
						watch->user_data);

			if ((event->mask & IN_ATTRIB) && watch->cb)
				watch->cb(watch, name, L_FSWATCH_EVENT_ATTRIB,
						watch->user_data);

			if (event->mask & IN_IGNORED) {
				stale_items = true;
				watch->cb = NULL;
			}
		}
	}

	in_notify = false;

	if (stale_items) {
		struct l_fswatch *watch;

		while ((watch = l_queue_remove_if(watches,
						l_fswatch_remove_func, NULL)))
			l_fswatch_free(watch);

		stale_items = false;

		if (l_queue_isempty(watches))
			l_fswatch_shutdown();
	}

	return true;
}

static void l_fswatch_io_destroy(void *user_data)
{
	l_queue_destroy(watches, l_fswatch_free);
	watches = NULL;
}

static bool l_fswatch_init(void)
{
	int inotify_fd = inotify_init1(IN_CLOEXEC);

	if (unlikely(inotify_fd < 0))
		return false;

	inotify_io = l_io_new(inotify_fd);
	if (unlikely(!inotify_io)) {
		close(inotify_fd);
		return false;
	}

	l_io_set_close_on_destroy(inotify_io, true);

	if (unlikely(!l_io_set_read_handler(inotify_io, inotify_read_cb,
						NULL, l_fswatch_io_destroy))) {
		l_io_destroy(inotify_io);
		return false;
	}

	return true;
}

LIB_EXPORT struct l_fswatch *l_fswatch_new(const char *path, l_fswatch_cb_t cb,
						void *user_data,
						l_fswatch_destroy_cb_t destroy)
{
	struct l_fswatch *watch;
	int id;

	if (unlikely(!cb))
		return NULL;

	if (!inotify_io && !l_fswatch_init())
		return NULL;

	/*
	 * inotify_watch_add already checks if the path is already being
	 * watched and will return the old watch ID so we're fine.
	 */
	id = inotify_add_watch(l_io_get_fd(inotify_io), path,
						EVENT_MASK | IN_EXCL_UNLINK);
	if (unlikely(id < 0)) {
		if (l_queue_isempty(watches))
			l_fswatch_shutdown();

		return NULL;
	}

	watch = l_new(struct l_fswatch, 1);
	watch->id = id;
	watch->cb = cb;
	watch->user_data = user_data;
	watch->destroy = destroy;

	if (!watches)
		watches = l_queue_new();

	l_queue_push_tail(watches, watch);

	return watch;
}

LIB_EXPORT void l_fswatch_destroy(struct l_fswatch *watch)
{
	const struct l_queue_entry *entry;
	int id;

	if (unlikely(!inotify_io || !watch))
		return;

	id = watch->id;

	/* Check if we have any other watch with the same inotify ID */
	for (entry = l_queue_get_entries(watches); entry;
			entry = entry->next) {
		struct l_fswatch *watch2 = entry->data;

		if (watch2 != watch && watch2->id == id)
			break;
	}

	if (!entry && id != -1)
		inotify_rm_watch(l_io_get_fd(inotify_io), id);

	if (in_notify) {
		watch->cb = NULL;
		stale_items = true;
		return;
	}

	l_queue_remove(watches, watch);
	l_fswatch_free(watch);

	if (l_queue_isempty(watches))
		l_fswatch_shutdown();
}
