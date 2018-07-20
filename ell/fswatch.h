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

#ifndef __ELL_FSWATCH_H
#define __ELL_FSWATCH_H

struct l_fswatch;

enum l_fswatch_event {
	L_FSWATCH_EVENT_CREATE,
	L_FSWATCH_EVENT_MOVE,
	L_FSWATCH_EVENT_MODIFY,
	L_FSWATCH_EVENT_DELETE,
};

typedef void (*l_fswatch_cb_t) (struct l_fswatch *watch, const char *filename,
				enum l_fswatch_event event, void *user_data);
typedef void (*l_fswatch_destroy_cb_t) (void *user_data);

struct l_fswatch *l_fswatch_new(const char *path, l_fswatch_cb_t cb,
				void *user_data,
				l_fswatch_destroy_cb_t destroy);
void l_fswatch_destroy(struct l_fswatch *watch);

#endif /* __ELL_FSWATCH_H */
