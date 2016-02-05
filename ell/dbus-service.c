/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2014  Intel Corporation. All rights reserved.
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
#include "dbus.h"
#include "dbus-service.h"
#include "dbus-private.h"
#include "private.h"

#define XML_ID "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
#define XML_DTD "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd"
#define XML_HEAD "<!DOCTYPE node PUBLIC \""XML_ID"\"\n\""XML_DTD"\">\n"

static const char *static_introspectable =
		"\t<interface name=\"org.freedesktop.DBus.Introspectable\">\n"
		"\t\t<method name=\"Introspect\">\n"
		"\t\t\t<arg name=\"xml\" type=\"s\" direction=\"out\"/>\n"
		"\t\t</method>\n\t</interface>\n";

struct _dbus_method {
	l_dbus_interface_method_cb_t cb;
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

struct l_dbus_interface {
	struct l_queue *methods;
	struct l_queue *signals;
	struct l_queue *properties;
	char name[];
};

struct child_node {
	struct object_node *node;
	struct child_node *next;
	char subpath[];
};

struct interface_instance {
	struct l_dbus_interface *interface;
	void *user_data;
	void (*user_destroy) (void *);
};

struct object_node {
	struct object_node *parent;
	struct l_queue *instances;
	struct child_node *children;
};

struct _dbus_object_tree {
	struct l_hashmap *interfaces;
	struct l_hashmap *objects;
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
					"type=\"%.*s\" direction=\"in\"/>\n",
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
					"type=\"%.*s\" direction=\"out\"/>\n",
					pname, (int) (end - sig + 1), sig);
		sig = end;
		offset += strlen(pname) + 1;
	}

	if (info->flags & L_DBUS_METHOD_FLAG_DEPRECATED)
		l_string_append(buf, "\t\t\t<annotation name=\""
				"org.freedesktop.DBus.Deprecated\" "
				"value=\"true\"/>\n");

	if (info->flags & L_DBUS_METHOD_FLAG_NOREPLY)
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

	if (info->flags & L_DBUS_SIGNAL_FLAG_DEPRECATED)
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

	if (info->flags & L_DBUS_PROPERTY_FLAG_WRITABLE)
		l_string_append(buf, "access=\"readwrite\"");
	else
		l_string_append(buf, "access=\"read\"");

	if (info->flags & L_DBUS_METHOD_FLAG_DEPRECATED) {
		l_string_append(buf, ">\n");
		l_string_append(buf, "\t\t\t<annotation name=\""
				"org.freedesktop.DBus.Deprecated\" "
				"value=\"true\"/>\n");
		l_string_append(buf, "\t\t</property>\n");
	} else
		l_string_append(buf, "/>\n");
}

void _dbus_interface_introspection(struct l_dbus_interface *interface,
						struct l_string *buf)
{
	l_string_append_printf(buf, "\t<interface name=\"%s\">\n",
				interface->name);

	l_queue_foreach(interface->methods,
		(l_queue_foreach_func_t) _dbus_method_introspection, buf);
	l_queue_foreach(interface->signals,
		(l_queue_foreach_func_t) _dbus_signal_introspection, buf);
	l_queue_foreach(interface->properties,
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

LIB_EXPORT bool l_dbus_interface_method(struct l_dbus_interface *interface,
					const char *name, uint32_t flags,
					l_dbus_interface_method_cb_t cb,
					const char *return_sig,
					const char *param_sig, ...)
{
	va_list args;
	unsigned int return_info_len;
	unsigned int param_info_len;
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
	return_info_len = strlen(return_sig) + 1;
	param_info_len = strlen(param_sig) + 1;

	va_start(args, param_sig);

	if (!size_params(return_sig, args, &return_info_len))
		goto error;

	if (!size_params(param_sig, args, &param_info_len))
		goto error;

	va_end(args);

	info = l_malloc(sizeof(*info) + return_info_len +
					param_info_len + strlen(name) + 1);
	info->cb = cb;
	info->flags = flags;
	info->name_len = strlen(name);
	strcpy(info->metainfo, name);

	va_start(args, param_sig);

	/*
	 * We store param signature + parameter names first, to speed up
	 * lookups during the message dispatch procedures.
	 */
	p = info->metainfo + info->name_len + param_info_len + 1;
	p = stpcpy(p, return_sig) + 1;
	p = copy_params(p, return_sig, args);

	p = info->metainfo + info->name_len + 1;
	p = stpcpy(p, param_sig) + 1;
	p = copy_params(p, param_sig, args);

	va_end(args);

	l_queue_push_tail(interface->methods, info);

	return true;

error:
	va_end(args);
	return false;
}

LIB_EXPORT bool l_dbus_interface_signal(struct l_dbus_interface *interface,
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

	l_queue_push_tail(interface->signals, info);

	return true;
}

LIB_EXPORT bool l_dbus_interface_property(struct l_dbus_interface *interface,
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

	l_queue_push_tail(interface->properties, info);

	return true;
}

LIB_EXPORT bool l_dbus_interface_ro_property(struct l_dbus_interface *interface,
						const char *name,
						const char *signature)
{
	return l_dbus_interface_property(interface, name, 0, signature);
}

LIB_EXPORT bool l_dbus_interface_rw_property(struct l_dbus_interface *interface,
						const char *name,
						const char *signature)
{
	return l_dbus_interface_property(interface, name,
					L_DBUS_PROPERTY_FLAG_WRITABLE,
					signature);
}

struct l_dbus_interface *_dbus_interface_new(const char *name)
{
	struct l_dbus_interface *interface;

	interface = l_malloc(sizeof(*interface) + strlen(name) + 1);

	interface->methods = l_queue_new();
	interface->signals = l_queue_new();
	interface->properties = l_queue_new();

	strcpy(interface->name, name);

	return interface;
}

void _dbus_interface_free(struct l_dbus_interface *interface)
{
	l_queue_destroy(interface->methods, l_free);
	l_queue_destroy(interface->signals, l_free);
	l_queue_destroy(interface->properties, l_free);

	l_free(interface);
}

static bool match_method(const void *a, const void *b)
{
	const struct _dbus_method *method = a;
	const char *name = b;

	if (!strcmp(method->metainfo, name))
		return true;

	return false;
}

struct _dbus_method *_dbus_interface_find_method(struct l_dbus_interface *i,
							const char *method)
{
	return l_queue_find(i->methods, match_method, (char *) method);
}

static bool match_signal(const void *a, const void *b)
{
	const struct _dbus_signal *signal = a;
	const char *name = b;

	if (!strcmp(signal->metainfo, name))
		return true;

	return false;
}

struct _dbus_signal *_dbus_interface_find_signal(struct l_dbus_interface *i,
							const char *signal)
{
	return l_queue_find(i->signals, match_signal, (char *) signal);
}

static bool match_property(const void *a, const void *b)
{
	const struct _dbus_property *property = a;
	const char *name = b;

	if (!strcmp(property->metainfo, name))
		return true;

	return false;
}

struct _dbus_property *_dbus_interface_find_property(struct l_dbus_interface *i,
							const char *property)
{
	return l_queue_find(i->properties, match_property, (char *) property);
}

static void interface_instance_free(struct interface_instance *instance)
{
	if (instance->user_destroy)
		instance->user_destroy(instance->user_data);

	l_free(instance);
}

static bool match_interface_instance(const void *a, const void *b)
{
	const struct interface_instance *instance = a;
	const char *name = b;

	if (!strcmp(instance->interface->name, name))
		return true;

	return false;
}

struct _dbus_object_tree *_dbus_object_tree_new()
{
	struct _dbus_object_tree *tree;

	tree = l_new(struct _dbus_object_tree, 1);

	tree->interfaces = l_hashmap_new();
	l_hashmap_set_hash_function(tree->interfaces, l_str_hash);
	l_hashmap_set_compare_function(tree->interfaces,
					(l_hashmap_compare_func_t)strcmp);

	tree->objects = l_hashmap_string_new();

	tree->root = l_new(struct object_node, 1);

	return tree;
}

static void subtree_free(struct object_node *node)
{
	struct child_node *child;

	while (node->children) {
		child = node->children;
		node->children = child->next;

		subtree_free(child->node);
		l_free(child);
	}

	l_queue_destroy(node->instances,
			(l_queue_destroy_func_t) interface_instance_free);

	l_free(node);
}

void _dbus_object_tree_free(struct _dbus_object_tree *tree)
{
	l_hashmap_destroy(tree->interfaces,
			(l_hashmap_destroy_func_t) _dbus_interface_free);
	l_hashmap_destroy(tree->objects, NULL);

	subtree_free(tree->root);

	l_free(tree);
}

static struct object_node *makepath_recurse(struct object_node *node,
						const char *path)
{
	const char *end;
	struct child_node *child;

	if (*path == '\0')
		return node;

	path += 1;
	end = strchrnul(path, '/');
	child = node->children;

	while (child) {
		if (!strncmp(child->subpath, path, end - path))
			goto done;

		child = child->next;
	}

	child = l_malloc(sizeof(*child) + end - path + 1);
	child->node = l_new(struct object_node, 1);
	child->node->parent = node;
	memcpy(child->subpath, path, end - path);
	child->subpath[end-path] = '\0';
	child->next = node->children;
	node->children = child;

done:
	return makepath_recurse(child->node, end);
}

struct object_node *_dbus_object_tree_makepath(struct _dbus_object_tree *tree,
						const char *path)
{
	if (path[0] == '/' && path[1] == '\0')
		return tree->root;

	return makepath_recurse(tree->root, path);
}

static struct object_node *lookup_recurse(struct object_node *node,
						const char *path)
{
	const char *end;
	struct child_node *child;

	if (*path == '\0')
		return node;

	path += 1;
	end = strchrnul(path, '/');
	child = node->children;

	while (child) {
		if (!strncmp(child->subpath, path, end - path))
			return lookup_recurse(child->node, end);

		child = child->next;
	}

	return NULL;
}

struct object_node *_dbus_object_tree_lookup(struct _dbus_object_tree *tree,
						const char *path)
{
	if (path[0] == '/' && path[1] == '\0')
		return tree->root;

	return lookup_recurse(tree->root, path);
}

void _dbus_object_tree_prune_node(struct object_node *node)
{
	struct object_node *parent = node->parent;
	struct child_node *p = NULL, *c;

	while (parent) {
		for (c = parent->children, p = NULL; c; p = c, c = c->next) {
			if (c->node != node)
				continue;

			if (p)
				p->next = c->next;
			else
				parent->children = c->next;

			subtree_free(c->node);
			l_free(c);

			break;
		}

		if (parent->children != NULL)
			return;

		if (parent->instances)
			return;

		node = parent;
		parent = node->parent;
	}
}

bool _dbus_object_tree_register(struct _dbus_object_tree *tree,
				const char *path, const char *interface,
				void (*setup_func)(struct l_dbus_interface *),
				void *user_data, void (*destroy) (void *))
{
	struct object_node *object;
	struct l_dbus_interface *dbi;
	const struct l_queue_entry *entry;
	struct interface_instance *instance;

	if (!_dbus_valid_interface(interface))
		return false;

	if (!_dbus_valid_object_path(path))
		return false;

	object = l_hashmap_lookup(tree->objects, path);
	if (!object) {
		object = _dbus_object_tree_makepath(tree, path);
		l_hashmap_insert(tree->objects, path, object);
	}

	/*
	 * Check to make sure we do not have this interface already
	 * registered for this object
	 */
	entry = l_queue_get_entries(object->instances);
	while (entry) {
		instance = entry->data;

		if (!strcmp(instance->interface->name, interface))
			return false;

		entry = entry->next;
	}

	dbi = l_hashmap_lookup(tree->interfaces, interface);
	if (!dbi) {
		dbi = _dbus_interface_new(interface);
		setup_func(dbi);
		l_hashmap_insert(tree->interfaces, dbi->name, dbi);
	}

	instance = l_new(struct interface_instance, 1);
	instance->interface = dbi;
	instance->user_destroy = destroy;
	instance->user_data = user_data;

	if (!object->instances)
		object->instances = l_queue_new();

	l_queue_push_tail(object->instances, instance);

	return true;
}

bool _dbus_object_tree_unregister(struct _dbus_object_tree *tree,
					const char *path,
					const char *interface)
{
	struct object_node *node;
	struct interface_instance *instance;
	bool r;

	node = l_hashmap_lookup(tree->objects, path);
	if (!node)
		return false;

	instance = l_queue_remove_if(node->instances,
			match_interface_instance, (char *) interface);

	r = instance ? true : false;

	if (instance)
		interface_instance_free(instance);

	if (l_queue_isempty(node->instances)) {
		l_hashmap_remove(tree->objects, path);

		if (!node->children)
			_dbus_object_tree_prune_node(node);
	}

	return r;
}

static void generate_interface_instance(void *data, void *user)
{
	struct interface_instance *instance = data;
	struct l_string *buf = user;

	_dbus_interface_introspection(instance->interface, buf);
}

void _dbus_object_tree_introspect(struct _dbus_object_tree *tree,
					const char *path, struct l_string *buf)
{
	struct object_node *node;
	struct child_node *child;

	node = l_hashmap_lookup(tree->objects, path);
	if (!node)
		node = _dbus_object_tree_lookup(tree, path);

	l_string_append(buf, XML_HEAD);
	l_string_append(buf, "<node>\n");

	if (node) {
		l_string_append(buf, static_introspectable);
		l_queue_foreach(node->instances,
					generate_interface_instance, buf);

		for (child = node->children; child; child = child->next)
			l_string_append_printf(buf, "\t<node name=\"%s\"/>\n",
						child->subpath);
	}

	l_string_append(buf, "</node>\n");
}

bool _dbus_object_tree_dispatch(struct _dbus_object_tree *tree,
					struct l_dbus *dbus,
					struct l_dbus_message *message)
{
	const char *path;
	const char *interface;
	const char *member;
	const char *msg_sig;
	const char *sig;
	struct object_node *node;
	struct interface_instance *instance;
	struct _dbus_method *method;
	struct l_dbus_message *reply;

	path = l_dbus_message_get_path(message);
	interface = l_dbus_message_get_interface(message);
	member = l_dbus_message_get_member(message);
	msg_sig = l_dbus_message_get_signature(message);

	if (!msg_sig)
		msg_sig = "";

	if (!strcmp(interface, "org.freedesktop.DBus.Introspectable") &&
			!strcmp(member, "Introspect") &&
			!strcmp(msg_sig, "")) {
		struct l_string *buf;
		char *xml;

		buf = l_string_new(0);
		_dbus_object_tree_introspect(tree, path, buf);
		xml = l_string_free(buf, false);

		reply = l_dbus_message_new_method_return(message);
		l_dbus_message_set_arguments(reply, "s", xml);
		l_dbus_send(dbus, reply);

		l_free(xml);

		return true;
	}

	node = l_hashmap_lookup(tree->objects, path);
	if (!node)
		return false;

	instance = l_queue_find(node->instances,
				match_interface_instance, (char *) interface);
	if (!instance)
		return false;

	method = _dbus_interface_find_method(instance->interface, member);
	if (!method)
		return false;

	sig = method->metainfo + method->name_len + 1;

	if (strcmp(msg_sig, sig))
		return false;

	reply = method->cb(dbus, message, instance->user_data);
	if (reply)
		l_dbus_send(dbus, reply);

	return true;
}
