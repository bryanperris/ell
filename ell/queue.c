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

#include "util.h"
#include "queue.h"
#include "private.h"

struct entry {
	void *data;
	struct entry *next;
};

struct l_queue {
	struct entry *head;
	struct entry *tail;
	unsigned int entries;
};

LIB_EXPORT struct l_queue *l_queue_new(void)
{
	struct l_queue *queue;

	queue = l_new(struct l_queue, 1);

	queue->head = NULL;
	queue->tail = NULL;
	queue->entries = 0;

	return queue;
}

LIB_EXPORT void l_queue_destroy(struct l_queue *queue,
				l_queue_destroy_func_t destroy)
{
	struct entry *entry;

	if (!queue)
		return;

	entry = queue->head;

	while (entry) {
		struct entry *tmp = entry;

		if (destroy)
			destroy(entry->data);

		entry = entry->next;

		l_free(tmp);
	}

	l_free(queue);
}

LIB_EXPORT bool l_queue_push_tail(struct l_queue *queue, void *data)
{
	struct entry *entry;

	if (!queue)
		return false;

	entry = l_new(struct entry, 1);

	entry->data = data;
	entry->next = NULL;

	if (queue->tail)
		queue->tail->next = entry;

	queue->tail = entry;

	if (!queue->head)
		queue->head = entry;

	queue->entries++;

	return true;
}

LIB_EXPORT void *l_queue_pop_head(struct l_queue *queue)
{
	struct entry *entry;
	void *data;

	if (!queue)
		return NULL;

	if (!queue->head)
		return NULL;

	entry = queue->head;

	if (!queue->head->next) {
		queue->head = NULL;
		queue->tail = NULL;
	} else
		queue->head = queue->head->next;

	data = entry->data;

	l_free(entry);

	queue->entries--;

	return data;
}

LIB_EXPORT bool l_queue_insert(struct l_queue *queue, void *data,
                        l_queue_compare_func_t function, void *user_data)
{
	struct entry *entry, *prev;

	if (!queue || !function)
		return false;

	entry = l_new(struct entry, 1);

	entry->data = data;
	entry->next = NULL;

	if (!queue->head) {
		queue->head = entry;
		queue->tail = entry;
		return true;
	}

	for (prev = queue->head; prev; prev = prev->next) {
		int match = function(entry, prev, user_data);

		if (match > 0) {
			if (prev == queue->head) {
				entry->next = queue->head;
				queue->head = entry;
				return true;
			}

			entry->next = prev->next;
			prev->next = entry;

			if (!entry->next)
				queue->tail = entry;

			return true;
		}
	}

	queue->tail->next = entry;
	queue->tail = entry;

	return true;
}

LIB_EXPORT bool l_queue_remove(struct l_queue *queue, void *data)
{
	struct entry *entry, *prev;

	if (!queue)
		return false;

	for (entry = queue->head, prev = NULL; entry;
					prev = entry, entry = entry->next) {
		if (entry->data != data)
			continue;

		if (prev)
			prev->next = entry->next;
		else
			queue->head = entry->next;

		if (!entry->next)
			queue->tail = prev;

		l_free(entry);

		return true;
	}

	return false;
}

LIB_EXPORT void l_queue_foreach(struct l_queue *queue,
			l_queue_foreach_func_t function, void *user_data)
{
	struct entry *entry;

	if (!queue || !function)
		return;

	for (entry = queue->head; entry; entry = entry->next)
		function(entry->data, user_data);
}

LIB_EXPORT void l_queue_foreach_remove(struct l_queue *queue,
                        l_queue_remove_func_t function, void *user_data)
{
	struct entry *entry, *prev = NULL;

	if (!queue || !function)
		return;

	entry = queue->head;

	while (entry) {
		if (function(entry, user_data)) {
			struct entry *tmp = entry;

			if (prev)
				prev->next = entry->next;
			else
				queue->head = entry->next;

			if (!entry->next)
				queue->tail = prev;

			entry = entry->next;

			l_free(tmp);
		} else {
			prev = entry;
			entry = entry->next;
		}
	}
}

LIB_EXPORT unsigned int l_queue_length(struct l_queue *queue)
{
	if (!queue)
		return 0;

	return queue->entries;
}

LIB_EXPORT bool l_queue_isempty(struct l_queue *queue)
{
	if (!queue)
		return true;

	return queue->entries == 0;
}
