/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
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

#ifndef __ELL_TIMEOUT_H
#define __ELL_TIMEOUT_H

#ifdef __cplusplus
extern "C" {
#endif

struct l_timeout;

typedef void (*l_timeout_notify_cb_t) (struct l_timeout *timeout,
						void *user_data);
typedef void (*l_timeout_destroy_cb_t) (void *user_data);

struct l_timeout *l_timeout_create(unsigned int seconds,
			l_timeout_notify_cb_t callback,
			void *user_data, l_timeout_destroy_cb_t destroy);
void l_timeout_modify(struct l_timeout *timeout,
				unsigned int seconds);
void l_timeout_remove(struct l_timeout *timeout);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_TIMEOUT_H */
