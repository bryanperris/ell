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

#ifndef __ELL_SERVICE_H
#define __ELL_SERVICE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct l_dbus;
struct l_dbus_service;
struct l_dbus_message;

enum l_dbus_service_method_flag {
	L_DBUS_SERVICE_METHOD_FLAG_DEPRECATED =	1,
	L_DBUS_SERVICE_METHOD_FLAG_NOREPLY =	2,
	L_DBUS_SERVICE_METHOD_FLAG_ASYNC =	4,
};

typedef void (*l_dbus_service_method_cb_t) (struct l_dbus *,
						struct l_dbus_message *message,
						void *user_data);

bool l_dbus_service_method(struct l_dbus_service *service, const char *name,
				uint32_t flags, l_dbus_service_method_cb_t cb,
				const char *return_sig, const char *param_sig,
				...);

bool l_dbus_service_signal(struct l_dbus_service *service, const char *name,
				uint32_t flags, const char *signature, ...);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_DBUS_SERVICE_H */
