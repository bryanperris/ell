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

struct l_string;
struct l_dbus_service;
struct _dbus_method;
struct l_dbus_service_signal;
struct l_dbus_service_property;

struct l_dbus_message *dbus_message_build(const void *data, size_t size);
bool dbus_message_compare(struct l_dbus_message *message,
					const void *data, size_t size);

const char *_dbus_signature_end(const char *signature);

bool _dbus_valid_object_path(const char *path);
bool _dbus_valid_signature(const char *sig);
bool _dbus_valid_interface(const char *interface);
bool _dbus_valid_method(const char *method);

void _dbus_method_introspection(struct _dbus_method *info,
					struct l_string *buf);
void _dbus_service_signal_introspection(struct l_dbus_service_signal *info,
					struct l_string *buf);
void _dbus_service_property_introspection(struct l_dbus_service_property *info,
						struct l_string *buf);
void _dbus_service_introspection(struct l_dbus_service *service,
						struct l_string *buf);

struct l_dbus_service *_dbus_service_new(const char *interface, void *user_data,
					void (*destroy) (void *));
void _dbus_service_free(struct l_dbus_service *service);

struct _dbus_method *_dbus_service_find_method(struct l_dbus_service *service,
						const char *method);
struct l_dbus_service_signal *_dbus_service_find_signal(
						struct l_dbus_service *service,
						const char *signal);
struct l_dbus_service_property *_dbus_service_find_property(
						struct l_dbus_service *service,
						const char *property);
