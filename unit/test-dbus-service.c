/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2012  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <stdbool.h>

#include <ell/ell.h>
#include <ell/dbus-service.h>
#include "ell/dbus-private.h"

struct l_dbus_service *service;

struct introspect_test {
	const char *name;
	const char *expected_xml;
};

static const struct introspect_test frobate_test = {
	.name = "Frobate",
	.expected_xml = "\t\t<method name=\"Frobate\">\n"
		"\t\t\t<arg name=\"bar\" type=\"s\" direction=\"out\"/>\n"
		"\t\t\t<arg name=\"baz\" type=\"a{us}\" direction=\"out\"/>\n"
		"\t\t\t<arg name=\"foo\" type=\"i\" direction=\"in\"/>\n"
		"\t\t\t<annotation name=\"org.freedesktop.DBus.Deprecated\" "
		"value=\"true\"/>\n"
		"\t\t</method>\n",
};

static const struct introspect_test bazify_test = {
	.name = "Bazify",
	.expected_xml = "\t\t<method name=\"Bazify\">\n"
		"\t\t\t<arg name=\"bar\" type=\"v\" direction=\"out\"/>\n"
		"\t\t\t<arg name=\"bar\" type=\"(iiu)\" direction=\"in\"/>\n"
		"\t\t</method>\n",
};

static const struct introspect_test mogrify_test = {
	.name = "Mogrify",
	.expected_xml = "\t\t<method name=\"Mogrify\">\n"
		"\t\t\t<arg name=\"bar\" type=\"(iiav)\" direction=\"in\"/>\n"
		"\t\t</method>\n",
};

static const struct introspect_test changed_test = {
	.name = "Changed",
	.expected_xml = "\t\t<signal name=\"Changed\">\n"
		"\t\t\t<arg name=\"new_value\" type=\"b\"/>\n"
		"\t\t</signal>\n",
};

static const struct introspect_test bar_test = {
	.name = "Bar",
	.expected_xml = "\t\t<property name=\"Bar\" type=\"y\" "
		"access=\"readwrite\"/>\n",
};

static const struct introspect_test interface_test = {
	.name = "",
	.expected_xml =
		"\t<interface name=\"org.freedesktop.SampleInterface\">\n"
		"\t\t<method name=\"Frobate\">\n"
		"\t\t\t<arg name=\"bar\" type=\"s\" direction=\"out\"/>\n"
		"\t\t\t<arg name=\"baz\" type=\"a{us}\" direction=\"out\"/>\n"
		"\t\t\t<arg name=\"foo\" type=\"i\" direction=\"in\"/>\n"
		"\t\t\t<annotation name=\"org.freedesktop.DBus.Deprecated\" "
		"value=\"true\"/>\n"
		"\t\t</method>\n"
		"\t\t<method name=\"Bazify\">\n"
		"\t\t\t<arg name=\"bar\" type=\"v\" direction=\"out\"/>\n"
		"\t\t\t<arg name=\"bar\" type=\"(iiu)\" direction=\"in\"/>\n"
		"\t\t</method>\n"
		"\t\t<method name=\"Mogrify\">\n"
		"\t\t\t<arg name=\"bar\" type=\"(iiav)\" direction=\"in\"/>\n"
		"\t\t</method>\n"
		"\t\t<signal name=\"Changed\">\n"
		"\t\t\t<arg name=\"new_value\" type=\"b\"/>\n"
		"\t\t</signal>\n"
		"\t\t<property name=\"Bar\" type=\"y\" "
		"access=\"readwrite\"/>\n"
		"\t</interface>\n",
};

static void test_introspect_method(const void *test_data)
{
	const struct introspect_test *test = test_data;
	struct _dbus_method *method;
	struct l_string *buf;
	char *xml;

	method = _dbus_service_find_method(service, test->name);
	assert(method);

	buf = l_string_new(0);
	_dbus_method_introspection(method, buf);
	xml = l_string_free(buf, false);

	assert(!strcmp(test->expected_xml, xml));
	l_free(xml);
}

static void test_introspect_signal(const void *test_data)
{
	const struct introspect_test *test = test_data;
	struct _dbus_signal *signal;
	struct l_string *buf;
	char *xml;

	signal = _dbus_service_find_signal(service, test->name);
	assert(signal);

	buf = l_string_new(0);
	_dbus_signal_introspection(signal, buf);
	xml = l_string_free(buf, false);

	assert(!strcmp(test->expected_xml, xml));
	l_free(xml);
}

static void test_introspect_property(const void *test_data)
{
	const struct introspect_test *test = test_data;
	struct _dbus_property *property;
	struct l_string *buf;
	char *xml;

	property = _dbus_service_find_property(service, test->name);
	assert(property);

	buf = l_string_new(0);
	_dbus_property_introspection(property, buf);
	xml = l_string_free(buf, false);

	assert(!strcmp(test->expected_xml, xml));
	l_free(xml);
}

static void test_introspect_interface(const void *test_data)
{
	const struct introspect_test *test = test_data;
	struct l_string *buf;
	char *xml;

	buf = l_string_new(0);
	_dbus_service_introspection(service, buf);
	xml = l_string_free(buf, false);

	assert(!strcmp(test->expected_xml, xml));
	l_free(xml);
}

int main(int argc, char *argv[])
{
	int ret;

	service = _dbus_service_new("org.freedesktop.SampleInterface",
					NULL, NULL);

	l_test_init(&argc, &argv);

	l_dbus_service_method(service, "Frobate",
				L_DBUS_SERVICE_METHOD_FLAG_DEPRECATED,
				NULL, "sa{us}", "i", "bar", "baz", "foo");
	l_dbus_service_method(service, "Bazify", 0, NULL, "v", "(iiu)",
				"bar", "bar");
	l_dbus_service_method(service, "Mogrify", 0, NULL, "", "(iiav)", "bar");

	l_dbus_service_signal(service, "Changed", 0, "b", "new_value");

	l_dbus_service_rw_property(service, "Bar", "y");

	l_test_add("Test Frobate Introspection", test_introspect_method,
			&frobate_test);
	l_test_add("Test Bazify Introspection", test_introspect_method,
			&bazify_test);
	l_test_add("Test Mogrify Introspection", test_introspect_method,
			&mogrify_test);

	l_test_add("Test Changed Introspection", test_introspect_signal,
			&changed_test);

	l_test_add("Test Bar Property Introspection", test_introspect_property,
			&bar_test);

	l_test_add("Test Interface Introspection", test_introspect_interface,
			&interface_test);

	ret = l_test_run();

	_dbus_service_free(service);

	return ret;
}
