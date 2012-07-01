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
#include <stdarg.h>
#include <string.h>

#include "util.h"
#include "queue.h"
#include "dbus-service.h"
#include "dbus-private.h"
#include "private.h"

struct l_dbus_service_method {
	l_dbus_service_method_cb_t cb;
	uint32_t flags;
	unsigned char name_len;
	char metainfo[];
};

struct l_dbus_service {
	struct l_queue *methods;
	void *user_data;
	void (*user_destroy) (void *data);
};

static char *copy_params(char *dest, const char *signature, va_list args)
{
	const char *pname;
	const char *sig;

	for (sig = signature; *sig; sig++) {
		sig = _dbus_signature_end(sig);
		if (!sig)
			return NULL;

		pname = va_arg(args, const char *);
		dest = stpcpy(dest, pname) + 1;
	}

	return dest;
}

static bool size_params(const char *signature, va_list args, unsigned int *len)
{
	const char *pname;
	const char *sig;

	for (sig = signature; *sig; sig++) {
		sig = _dbus_signature_end(sig);
		if (!sig)
			return false;

		pname = va_arg(args, const char *);
		*len += strlen(pname) + 1;
	}

	return true;
}

bool l_dbus_service_method(struct l_dbus_service *service, const char *name,
				uint32_t flags, l_dbus_service_method_cb_t cb,
				const char *return_sig, const char *param_sig,
				...)
{
	va_list args;
	unsigned int metainfo_len;
	struct l_dbus_service_method *info;
	char *p;

	if (!_dbus_valid_method(name))
		return false;

	if (unlikely(!return_sig || !param_sig))
		return false;

	if (return_sig[0] && !_dbus_valid_signature(return_sig))
		return false;

	if (param_sig[0] && !_dbus_valid_signature(param_sig))
		return false;

	/* Pre-calculate the needed meta-info length */
	metainfo_len = strlen(name) + 1;
	metainfo_len += strlen(return_sig) + 1;
	metainfo_len += strlen(param_sig) + 1;

	va_start(args, param_sig);

	if (!size_params(return_sig, args, &metainfo_len))
		goto error;

	if (!size_params(param_sig, args, &metainfo_len))
		goto error;

	va_end(args);

	info = l_malloc(sizeof(*info) + metainfo_len);
	info->cb = cb;
	info->flags = flags;
	info->name_len = strlen(name);

	p = stpcpy(info->metainfo, name) + 1;

	va_start(args, param_sig);
	p = stpcpy(p, return_sig) + 1;
	p = copy_params(p, return_sig, args);
	p = stpcpy(p, param_sig) + 1;
	p = copy_params(p, param_sig, args);
	va_end(args);

	l_queue_push_tail(service->methods, info);

	return true;

error:
	va_end(args);
	return false;
}

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