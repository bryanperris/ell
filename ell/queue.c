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

#include <stdlib.h>
#include <string.h>

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

	queue = malloc(sizeof(struct l_queue));
	if (!queue)
		return NULL;

	memset(queue, 0, sizeof(struct l_queue));
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

		free(tmp);
	}

	free(queue);
}

LIB_EXPORT bool l_queue_push_tail(struct l_queue *queue, void *data)
{
	struct entry *entry;

	if (!queue)
		return false;

	entry = malloc(sizeof(struct entry));
	if (!entry)
		return false;

	memset(entry, 0, sizeof(struct entry));
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

	free(entry);

	queue->entries--;

	return data;
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

		free(entry);

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
