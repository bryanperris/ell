/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2015  Intel Corporation. All rights reserved.
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

#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <assert.h>
#include <time.h>
#include <stdio.h>

#include <ell/ell.h>
#include "ell/dbus-private.h"

#define DBUS_SERVICE_DBUS	"org.freedesktop.DBus"
#define DBUS_PATH_DBUS		"/org/freedesktop/DBus"
#define DBUS_INTERFACE_DBUS	"org.freedesktop.DBus"
#define DBUS_MAXIMUM_MATCH_RULE_LENGTH	1024

struct watch_test {
	const char *name;
	const char *service;
	const char *path;
	const char *interface;
	const char *method;
	const char *expected;
};

static const struct watch_test match_test_1 = {
	.name = ":1.101",
	.service = DBUS_SERVICE_DBUS,
	.path = DBUS_PATH_DBUS,
	.interface = DBUS_INTERFACE_DBUS,
	.method = "NameOwnerChanged",
	.expected = "type='signal',"
		"sender='org.freedesktop.DBus',"
		"path='/org/freedesktop/DBus',"
		"interface='org.freedesktop.DBus',"
		"member='NameOwnerChanged',"
		"arg0=':1.101'",
};

static const struct watch_test match_test_2 = {
	.name = ":1.102",
	.service = NULL,
	.path = DBUS_PATH_DBUS,
	.interface = DBUS_INTERFACE_DBUS,
	.method = "NameOwnerChanged",
	.expected = "type='signal',"
		"path='/org/freedesktop/DBus',"
		"interface='org.freedesktop.DBus',"
		"member='NameOwnerChanged',"
		"arg0=':1.102'",
};

static const struct watch_test match_test_3 = {
	.name = ":1.102",
	.service = DBUS_SERVICE_DBUS,
	.path = NULL,
	.interface = DBUS_INTERFACE_DBUS,
	.method = "NameOwnerChanged",
	.expected = "type='signal',"
		"sender='org.freedesktop.DBus',"
		"interface='org.freedesktop.DBus',"
		"member='NameOwnerChanged',"
		"arg0=':1.102'",
};

static const struct watch_test match_test_4 = {
	.name = ":1.102",
	.service = DBUS_SERVICE_DBUS,
	.path = DBUS_PATH_DBUS,
	.interface = NULL,
	.method = "NameOwnerChanged",
	.expected = "type='signal',"
		"sender='org.freedesktop.DBus',"
		"path='/org/freedesktop/DBus',"
		"member='NameOwnerChanged',"
		"arg0=':1.102'",
};

static const struct watch_test match_test_5 = {
	.name = ":1.102",
	.service = DBUS_SERVICE_DBUS,
	.path = DBUS_PATH_DBUS,
	.interface = DBUS_INTERFACE_DBUS,
	.method = NULL,
	.expected = "type='signal',"
		"sender='org.freedesktop.DBus',"
		"path='/org/freedesktop/DBus',"
		"interface='org.freedesktop.DBus',"
		"arg0=':1.102'",
};

static const struct watch_test match_test_6 = {
	.name = NULL,
	.service = DBUS_SERVICE_DBUS,
	.path = DBUS_PATH_DBUS,
	.interface = DBUS_INTERFACE_DBUS,
	.method = "NameOwnerChanged",
	.expected = "type='signal',"
		"sender='org.freedesktop.DBus',"
		"path='/org/freedesktop/DBus',"
		"interface='org.freedesktop.DBus',"
		"member='NameOwnerChanged'",
};

static const struct watch_test match_test_7 = {
	.name = ":1.101",
	.service = NULL,
	.path = NULL,
	.interface = DBUS_INTERFACE_DBUS,
	.method = "NameOwnerChanged",
	.expected = "type='signal',"
		"interface='org.freedesktop.DBus',"
		"member='NameOwnerChanged',"
		"arg0=':1.101'",
};

static const struct watch_test match_test_8 = {
	.name = ":1.101",
	.service = NULL,
	.path = NULL,
	.interface = NULL,
	.method = "NameOwnerChanged",
	.expected = "type='signal',"
		"member='NameOwnerChanged',"
		"arg0=':1.101'",
};

static const struct watch_test match_test_9 = {
	.name = NULL,
	.service = NULL,
	.path = NULL,
	.interface = NULL,
	.method = NULL,
	.expected = "type='signal'",
};

static void test_match(const void *test_data)
{
	const struct watch_test *test = test_data;
	struct dbus1_filter_data *data;
	char rule[DBUS_MAXIMUM_MATCH_RULE_LENGTH];

	data = _dbus1_filter_data_get(NULL,
				NULL,
				test->service,
				test->path,
				test->interface,
				test->method,
				test->name,
				NULL,
				NULL,
				NULL);

	_dbus1_filter_format_match(data, rule, sizeof(rule));

	assert(strcmp(rule, test->expected) == 0);

	_dbus1_filter_data_destroy(data);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("DBus filter NameOwnerChanged", test_match, &match_test_1);
	l_test_add("DBus filter NULL service", test_match, &match_test_2);
	l_test_add("DBus filter NULL path", test_match, &match_test_3);
	l_test_add("DBus filter NULL interface", test_match, &match_test_4);
	l_test_add("DBus filter NULL method", test_match, &match_test_5);
	l_test_add("DBus filter NULL argument", test_match, &match_test_6);
	l_test_add("DBus filter NULL service and path", test_match,
								&match_test_7);
	l_test_add("DBus filter NULL service, path and interface", test_match,
								&match_test_8);
	l_test_add("DBus filter NULL all fields", test_match, &match_test_9);

	return l_test_run();
}
