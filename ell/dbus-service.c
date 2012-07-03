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
#include "string.h"
#include "hashmap.h"
#include "dbus-service.h"
#include "dbus-private.h"
#include "private.h"

struct _dbus_method {
	l_dbus_service_method_cb_t cb;
	uint32_t flags;
	unsigned char name_len;
	char metainfo[];
};

struct _dbus_signal {
	uint32_t flags;
	unsigned char name_len;
	char metainfo[];
};

struct _dbus_property {
	uint32_t flags;
	unsigned char name_len;
	char metainfo[];
};

struct l_dbus_service {
	char *interface;
	struct l_queue *methods;
	struct l_queue *signals;
	struct l_queue *properties;
	void *user_data;
	void (*user_destroy) (void *data);
};

struct child_node {
	struct object_node *node;
	struct child_node *next;
	char subpath[];
};

struct object_node {
	struct l_queue *interfaces;
	struct child_node *children;
};

struct _dbus_object_tree {
	struct l_hashmap *interfaces;
	struct object_node *root;
};

void _dbus_method_introspection(struct _dbus_method *info,
					struct l_string *buf)
{
	const char *sig;
	const char *end;
	const char *pname;
	unsigned int offset = info->name_len + 1;

	l_string_append_printf(buf, "\t\t<method name=\"%s\">\n",
				info->metainfo);

	sig = info->metainfo + offset;
	offset += strlen(sig) + 1;

	for (; *sig; sig++) {
		end = _dbus_signature_end(sig);
		pname = info->metainfo + offset;

		l_string_append_printf(buf, "\t\t\t<arg name=\"%s\" "
					"type=\"%.*s\" direction=\"out\"/>\n",
					pname, (int) (end - sig + 1), sig);
		sig = end;
		offset += strlen(pname) + 1;
	}

	sig = info->metainfo + offset;
	offset += strlen(sig) + 1;

	for (; *sig; sig++) {
		end = _dbus_signature_end(sig);
		pname = info->metainfo + offset;

		l_string_append_printf(buf, "\t\t\t<arg name=\"%s\" "
					"type=\"%.*s\" direction=\"in\"/>\n",
					pname, (int) (end - sig + 1), sig);
		sig = end;
		offset += strlen(pname) + 1;
	}

	if (info->flags & L_DBUS_SERVICE_METHOD_FLAG_DEPRECATED)
		l_string_append(buf, "\t\t\t<annotation name=\""
				"org.freedesktop.DBus.Deprecated\" "
				"value=\"true\"/>\n");

	if (info->flags & L_DBUS_SERVICE_METHOD_FLAG_NOREPLY)
		l_string_append(buf, "\t\t\t<annotation name=\""
				"org.freedesktop.DBus.Method.NoReply\" "
				"value=\"true\"/>\n");

	l_string_append(buf, "\t\t</method>\n");
}

void _dbus_signal_introspection(struct _dbus_signal *info,
					struct l_string *buf)
{
	const char *sig;
	const char *end;
	const char *pname;
	unsigned int offset = info->name_len + 1;

	l_string_append_printf(buf, "\t\t<signal name=\"%s\">\n",
				info->metainfo);

	sig = info->metainfo + offset;
	offset += strlen(sig) + 1;

	for (; *sig; sig++) {
		end = _dbus_signature_end(sig);
		pname = info->metainfo + offset;

		l_string_append_printf(buf, "\t\t\t<arg name=\"%s\" "
					"type=\"%.*s\"/>\n",
					pname, (int) (end - sig + 1), sig);
		sig = end;
		offset += strlen(pname) + 1;
	}

	if (info->flags & L_DBUS_SERVICE_SIGNAL_FLAG_DEPRECATED)
		l_string_append(buf, "\t\t\t<annotation name=\""
				"org.freedesktop.DBus.Deprecated\" "
				"value=\"true\"/>\n");

	l_string_append(buf, "\t\t</signal>\n");
}

void _dbus_property_introspection(struct _dbus_property *info,
						struct l_string *buf)
{
	unsigned int offset = info->name_len + 1;
	const char *signature = info->metainfo + offset;

	l_string_append_printf(buf, "\t\t<property name=\"%s\" type=\"%s\" ",
				info->metainfo, signature);

	if (info->flags & L_DBUS_SERVICE_PROPERTY_FLAG_WRITABLE)
		l_string_append(buf, "access=\"readwrite\"");
	else
		l_string_append(buf, "access=\"read\"");

	if (info->flags & L_DBUS_SERVICE_METHOD_FLAG_DEPRECATED) {
		l_string_append(buf, ">\n");
		l_string_append(buf, "\t\t\t<annotation name=\""
				"org.freedesktop.DBus.Deprecated\" "
				"value=\"true\"/>\n");
		l_string_append(buf, "\t\t</property>\n");
	} else
		l_string_append(buf, "/>\n");
}

void _dbus_service_introspection(struct l_dbus_service *service,
						struct l_string *buf)
{
	l_string_append_printf(buf, "\t<interface name=\"%s\">\n",
				service->interface);

	l_queue_foreach(service->methods,
		(l_queue_foreach_func_t) _dbus_method_introspection, buf);
	l_queue_foreach(service->signals,
		(l_queue_foreach_func_t) _dbus_signal_introspection, buf);
	l_queue_foreach(service->properties,
		(l_queue_foreach_func_t) _dbus_property_introspection, buf);

	l_string_append(buf, "\t</interface>\n");
}

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

LIB_EXPORT bool l_dbus_service_method(struct l_dbus_service *service,
					const char *name, uint32_t flags,
					l_dbus_service_method_cb_t cb,
					const char *return_sig,
					const char *param_sig, ...)
{
	va_list args;
	unsigned int metainfo_len;
	struct _dbus_method *info;
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

LIB_EXPORT bool l_dbus_service_signal(struct l_dbus_service *service,
					const char *name, uint32_t flags,
					const char *signature, ...)
{
	va_list args;
	unsigned int metainfo_len;
	struct _dbus_signal *info;
	char *p;

	if (!_dbus_valid_method(name))
		return false;

	if (unlikely(!signature))
		return false;

	if (signature[0] && !_dbus_valid_signature(signature))
		return false;

	/* Pre-calculate the needed meta-info length */
	metainfo_len = strlen(name) + 1;
	metainfo_len += strlen(signature) + 1;

	va_start(args, signature);

	if (!size_params(signature, args, &metainfo_len)) {
		va_end(args);
		return false;
	}

	va_end(args);

	info = l_malloc(sizeof(*info) + metainfo_len);
	info->flags = flags;
	info->name_len = strlen(name);

	p = stpcpy(info->metainfo, name) + 1;

	va_start(args, signature);
	p = stpcpy(p, signature) + 1;
	p = copy_params(p, signature, args);
	va_end(args);

	l_queue_push_tail(service->signals, info);

	return true;
}

LIB_EXPORT bool l_dbus_service_property(struct l_dbus_service *service,
					const char *name, uint32_t flags,
					const char *signature)
{
	unsigned int metainfo_len;
	struct _dbus_property *info;
	char *p;

	if (!_dbus_valid_method(name))
		return false;

	if (unlikely(!signature))
		return false;

	if (!_dbus_valid_signature(signature))
		return false;

	/* Pre-calculate the needed meta-info length */
	metainfo_len = strlen(name) + 1;
	metainfo_len += strlen(signature) + 1;

	info = l_malloc(sizeof(*info) + metainfo_len);
	info->flags = flags;
	info->name_len = strlen(name);

	p = stpcpy(info->metainfo, name) + 1;
	strcpy(p, signature);

	l_queue_push_tail(service->properties, info);

	return true;
}

LIB_EXPORT bool l_dbus_service_ro_property(struct l_dbus_service *service,
						const char *name,
						const char *signature)
{
	return l_dbus_service_property(service, name, 0, signature);
}

LIB_EXPORT bool l_dbus_service_rw_property(struct l_dbus_service *service,
						const char *name,
						const char *signature)
{
	return l_dbus_service_property(service, name,
					L_DBUS_SERVICE_PROPERTY_FLAG_WRITABLE,
					signature);
}

struct l_dbus_service *_dbus_service_new(const char *interface, void *user_data,
					void (*destroy) (void *))
{
	struct l_dbus_service *service;

	service = l_new(struct l_dbus_service, 1);

	service->interface = l_strdup(interface);

	service->methods = l_queue_new();
	service->signals = l_queue_new();
	service->properties = l_queue_new();

	service->user_data = user_data;
	service->user_destroy = destroy;

	return service;
}

void _dbus_service_free(struct l_dbus_service *service)
{
	if (service->user_destroy)
		service->user_destroy(service->user_data);

	l_queue_destroy(service->methods, l_free);
	l_queue_destroy(service->signals, l_free);
	l_queue_destroy(service->properties, l_free);

	l_free(service);
}

static bool match_method(const void *a, const void *b)
{
	const struct _dbus_method *method = a;
	const char *name = b;

	if (!strcmp(method->metainfo, name))
		return true;

	return false;
}

struct _dbus_method *_dbus_service_find_method(struct l_dbus_service *service,
						const char *method)
{
	return l_queue_find(service->methods, match_method, method);
}

static bool match_signal(const void *a, const void *b)
{
	const struct _dbus_signal *signal = a;
	const char *name = b;

	if (!strcmp(signal->metainfo, name))
		return true;

	return false;
}

struct _dbus_signal *_dbus_service_find_signal(struct l_dbus_service *service,
						const char *signal)
{
	return l_queue_find(service->signals, match_signal, signal);
}

static bool match_property(const void *a, const void *b)
{
	const struct _dbus_property *property = a;
	const char *name = b;

	if (!strcmp(property->metainfo, name))
		return true;

	return false;
}

struct _dbus_property *_dbus_service_find_property(
						struct l_dbus_service *service,
						const char *property)
{
	return l_queue_find(service->properties, match_property, property);
}

struct _dbus_object_tree *_dbus_object_tree_new()
{
	struct _dbus_object_tree *tree;

	tree = l_new(struct _dbus_object_tree, 1);

	tree->interfaces = l_hashmap_new();
	l_hashmap_set_hash_function(tree->interfaces, l_str_hash);
	l_hashmap_set_compare_function(tree->interfaces,
					(l_hashmap_compare_func_t)strcmp);

	return tree;
}

void _dbus_object_tree_free(struct _dbus_object_tree *tree)
{
	l_hashmap_destroy(tree->interfaces,
				(l_hashmap_destroy_func_t) _dbus_service_free);

	l_free(tree);
}

bool _dbus_object_tree_register(struct _dbus_object_tree *tree,
				const char *path, const char *interface,
				void (*setup_func)(struct l_dbus_service *),
				void *user_data, void (*destroy) (void *))
{
	return false;
}

bool _dbus_object_tree_unregister(struct _dbus_object_tree *tree,
					const char *path,
					const char *interface)
{
	return false;
}
