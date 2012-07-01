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

#define _GNU_SOURCE

#include "util.h"
#include "queue.h"
#include "dbus-service.h"
#include "dbus-private.h"
#include "private.h"

struct l_dbus_service {
	struct l_queue *methods;
	void *user_data;
	void (*user_destroy) (void *data);
};

struct l_dbus_service *_dbus_service_new(const char *interface, void *user_data,
					void (*destroy) (void *))
{
	struct l_dbus_service *service;

	service = l_new(struct l_dbus_service, 1);
	service->methods = l_queue_new();
	service->user_data = user_data;
	service->user_destroy = destroy;

	return service;
}

void _dbus_service_free(struct l_dbus_service *service)
{
	if (service->user_destroy)
		service->user_destroy(service->user_data);

	l_queue_destroy(service->methods, l_free);
	l_free(service);
}
