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

#include <stdint.h>

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define align_len(len, boundary) (((len)+(boundary)-1) & ~((boundary)-1))

#define LIB_EXPORT __attribute__ ((visibility("default")))

struct l_debug_desc;

void debug_enable(struct l_debug_desc *start, struct l_debug_desc *stop);

void plugin_update_debug(void);

typedef void (*watch_event_cb_t) (int fd, uint32_t events, void *user_data);
typedef void (*watch_destroy_cb_t) (void *user_data);

typedef void (*idle_event_cb_t) (void *user_data);
typedef void (*idle_destroy_cb_t) (void *user_data);

int watch_add(int fd, uint32_t events, watch_event_cb_t callback,
				void *user_data, watch_destroy_cb_t destroy);
int watch_modify(int fd, uint32_t events);
int watch_remove(int fd);

int idle_add(idle_event_cb_t callback, void *user_data,
		idle_destroy_cb_t destroy);
void idle_remove(int id);

struct l_dbus_message *dbus_message_build(const void *data, size_t size);
bool dbus_message_compare(struct l_dbus_message *message,
					const void *data, size_t size);

bool _dbus_valid_object_path(const char *path);
