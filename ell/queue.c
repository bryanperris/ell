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

#include "util.h"
#include "queue.h"
#include "private.h"

/**
 * SECTION:queue
 * @short_description: Queue support
 *
 * Queue support
 */

struct entry {
	void *data;
	struct entry *next;
};

/**
 * l_queue:
 *
 * Opague object representing the queue.
 */
struct l_queue {
	struct entry *head;
	struct entry *tail;
	unsigned int entries;
};

/**
 * l_queue_new:
 *
 * Create a new queue.
 *
 * No error handling is needed since. In case of real memory allocation
 * problems abort() will be called.
 *
 * Returns: a newly allocated #l_queue object
 **/
LIB_EXPORT struct l_queue *l_queue_new(void)
{
	struct l_queue *queue;

	queue = l_new(struct l_queue, 1);

	queue->head = NULL;
	queue->tail = NULL;
	queue->entries = 0;

	return queue;
}

/**
 * l_queue_destroy:
 * @queue: queue object
 * @destroy: destroy function
 *
 * Free queue and call @destory on all remaining entries.
 **/
LIB_EXPORT void l_queue_destroy(struct l_queue *queue,
				l_queue_destroy_func_t destroy)
{
	struct entry *entry;

	if (unlikely(!queue))
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

/**
 * l_queue_push_tail:
 * @queue: queue object
 * @data: pointer to data
 *
 * Adds @data pointer at the end of the queue.
 *
 * Returns: #true when data has been added and #false in case an invalid
 *          @queue object has been provided
 **/
LIB_EXPORT bool l_queue_push_tail(struct l_queue *queue, void *data)
{
	struct entry *entry;

	if (unlikely(!queue))
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

/**
 * l_queue_push_head:
 * @queue: queue object
 * @data: pointer to data
 *
 * Adds @data pointer at the start of the queue.
 *
 * Returns: #true when data has been added and #false in case an invalid
 *          @queue object has been provided
 **/
LIB_EXPORT bool l_queue_push_head(struct l_queue *queue, void *data)
{
	struct entry *entry;

	if (unlikely(!queue))
		return false;

	entry = l_new(struct entry, 1);

	entry->data = data;
	entry->next = queue->head;

	queue->head = entry;

	if (!queue->tail)
		queue->tail = entry;

	queue->entries++;

	return true;
}

/**
 * l_queue_pop_head:
 * @queue: queue object
 *
 * Removes the first element of the queue an returns it.
 *
 * Returns: data pointer to first element or #NULL in case an empty queue
 **/
LIB_EXPORT void *l_queue_pop_head(struct l_queue *queue)
{
	struct entry *entry;
	void *data;

	if (unlikely(!queue))
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

/**
 * l_queue_insert:
 * @queue: queue object
 * @data: pointer to data
 * @function: compare function
 * @user_data: user data given to compare function
 *
 * Inserts @data pointer at a position in the queue determined by the
 * compare @function.
 *
 * Returns: #true when data has been added and #false in case of failure
 **/
LIB_EXPORT bool l_queue_insert(struct l_queue *queue, void *data,
                        l_queue_compare_func_t function, void *user_data)
{
	struct entry *entry, *prev;

	if (unlikely(!queue || !function))
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
		int match = function(entry->data, prev->data, user_data);

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

/**
 * l_queue_remove:
 * @queue: queue object
 * @data: pointer to data
 *
 * Remove given @data from the queue.
 *
 * Returns: #true when data has been removed and #false when data could not
 *          be found or an invalid @queue object has been provided
 **/
LIB_EXPORT bool l_queue_remove(struct l_queue *queue, void *data)
{
	struct entry *entry, *prev;

	if (unlikely(!queue))
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

/**
 * l_queue_reverse:
 * @queue: queue object
 *
 * Reverse entries in the queue.
 *
 * Returns: #true on success and #false on failure
 **/
LIB_EXPORT bool l_queue_reverse(struct l_queue *queue)
{
	struct entry *entry, *prev = NULL;

	if (unlikely(!queue))
		return false;

	entry = queue->head;

	while (entry) {
		struct entry *next = entry->next;

		entry->next = prev;

		prev = entry;
		entry = next;
	}

	queue->tail = queue->head;
	queue->head = prev;

	return true;
}

/**
 * l_queue_foreach:
 * @queue: queue object
 * @function: callback function
 * @user_data: user data given to callback function
 *
 * Call @function for every given data in @queue.
 **/
LIB_EXPORT void l_queue_foreach(struct l_queue *queue,
			l_queue_foreach_func_t function, void *user_data)
{
	struct entry *entry;

	if (unlikely(!queue || !function))
		return;

	for (entry = queue->head; entry; entry = entry->next)
		function(entry->data, user_data);
}

/**
 * l_queue_foreach_remove:
 * @queue: queue object
 * @function: callback function
 * @user_data: user data given to callback function
 *
 * Remove all entries in the @queue where @function returns #true.
 *
 * Returns: number of removed entries
 **/
LIB_EXPORT unsigned int l_queue_foreach_remove(struct l_queue *queue,
                        l_queue_remove_func_t function, void *user_data)
{
	struct entry *entry, *prev = NULL;
	unsigned int count = 0;

	if (unlikely(!queue || !function))
		return 0;

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

			count++;
		} else {
			prev = entry;
			entry = entry->next;
		}
	}

	return count;
}

/**
 * l_queue_length:
 * @queue: queue object
 *
 * Returns: entries of the queue
 **/
LIB_EXPORT unsigned int l_queue_length(struct l_queue *queue)
{
	if (unlikely(!queue))
		return 0;

	return queue->entries;
}

/**
 * l_queue_isempty:
 * @queue: queue object
 *
 * Returns: #true if @queue is empty and #false is not
 **/
LIB_EXPORT bool l_queue_isempty(struct l_queue *queue)
{
	if (unlikely(!queue))
		return true;

	return queue->entries == 0;
}
