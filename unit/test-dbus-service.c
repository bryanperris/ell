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
#include <assert.h>
#include <stdbool.h>

#include <ell/ell.h>
#include "ell/dbus-private.h"

struct l_dbus_interface *interface;
static bool callback_called = false;
static char *dummy_data = "Foobar";

struct introspect_test {
	const char *name;
	const char *expected_xml;
};

static const struct introspect_test frobate_test = {
	.name = "Frobate",
	.expected_xml = "\t\t<method name=\"Frobate\">\n"
		"\t\t\t<arg name=\"foo\" type=\"i\" direction=\"in\"/>\n"
		"\t\t\t<arg name=\"bar\" type=\"s\" direction=\"out\"/>\n"
		"\t\t\t<arg name=\"baz\" type=\"a{us}\" direction=\"out\"/>\n"
		"\t\t\t<annotation name=\"org.freedesktop.DBus.Deprecated\" "
		"value=\"true\"/>\n"
		"\t\t</method>\n",
};

static const struct introspect_test bazify_test = {
	.name = "Bazify",
	.expected_xml = "\t\t<method name=\"Bazify\">\n"
		"\t\t\t<arg name=\"bar\" type=\"(iiu)\" direction=\"in\"/>\n"
		"\t\t\t<arg name=\"bar\" type=\"v\" direction=\"out\"/>\n"
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
		"\t\t\t<arg name=\"foo\" type=\"i\" direction=\"in\"/>\n"
		"\t\t\t<arg name=\"bar\" type=\"s\" direction=\"out\"/>\n"
		"\t\t\t<arg name=\"baz\" type=\"a{us}\" direction=\"out\"/>\n"
		"\t\t\t<annotation name=\"org.freedesktop.DBus.Deprecated\" "
		"value=\"true\"/>\n"
		"\t\t</method>\n"
		"\t\t<method name=\"Bazify\">\n"
		"\t\t\t<arg name=\"bar\" type=\"(iiu)\" direction=\"in\"/>\n"
		"\t\t\t<arg name=\"bar\" type=\"v\" direction=\"out\"/>\n"
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

	method = _dbus_interface_find_method(interface, test->name);
	assert(method);

	buf = l_string_new(0);
	_dbus_method_introspection(method, buf);
	xml = l_string_unwrap(buf);

	assert(!strcmp(test->expected_xml, xml));
	l_free(xml);
}

static void test_introspect_signal(const void *test_data)
{
	const struct introspect_test *test = test_data;
	struct _dbus_signal *signal;
	struct l_string *buf;
	char *xml;

	signal = _dbus_interface_find_signal(interface, test->name);
	assert(signal);

	buf = l_string_new(0);
	_dbus_signal_introspection(signal, buf);
	xml = l_string_unwrap(buf);

	assert(!strcmp(test->expected_xml, xml));
	l_free(xml);
}

static void test_introspect_property(const void *test_data)
{
	const struct introspect_test *test = test_data;
	struct _dbus_property *property;
	struct l_string *buf;
	char *xml;

	property = _dbus_interface_find_property(interface, test->name);
	assert(property);

	buf = l_string_new(0);
	_dbus_property_introspection(property, buf);
	xml = l_string_unwrap(buf);

	assert(!strcmp(test->expected_xml, xml));
	l_free(xml);
}

static void test_introspect_interface(const void *test_data)
{
	const struct introspect_test *test = test_data;
	struct l_string *buf;
	char *xml;

	buf = l_string_new(0);
	_dbus_interface_introspection(interface, buf);
	xml = l_string_unwrap(buf);

	assert(!strcmp(test->expected_xml, xml));
	l_free(xml);
}

static void test_dbus_object_tree_1(const void *test_data)
{
	struct _dbus_object_tree *tree;
	struct object_node *leaf1, *leaf2, *leaf3;
	struct object_node *tmp;

	tree = _dbus_object_tree_new();
	assert(tree);

	leaf1 = _dbus_object_tree_makepath(tree, "/foo/bar/baz");
	leaf2 = _dbus_object_tree_makepath(tree, "/foo/bar/ble");
	leaf3 = _dbus_object_tree_makepath(tree, "/foo/bee/boo");

	tmp = _dbus_object_tree_lookup(tree, "/foo");
	assert(tmp);

	tmp = _dbus_object_tree_lookup(tree, "/foo/bar/baz");
	assert(tmp);
	assert(tmp == leaf1);

	tmp = _dbus_object_tree_lookup(tree, "/foo/bar/ble");
	assert(tmp);
	assert(tmp == leaf2);

	tmp = _dbus_object_tree_lookup(tree, "/foo/bee/boo");
	assert(tmp);
	assert(tmp == leaf3);

	tmp = _dbus_object_tree_lookup(tree, "/foobar");
	assert(!tmp);

	tmp = _dbus_object_tree_lookup(tree, "/foo/bee");
	assert(tmp);
	_dbus_object_tree_prune_node(leaf3);
	tmp = _dbus_object_tree_lookup(tree, "/foo/bee");
	assert(!tmp);

	tmp = _dbus_object_tree_lookup(tree, "/foo/bar");
	assert(tmp);
	_dbus_object_tree_prune_node(leaf2);
	tmp = _dbus_object_tree_lookup(tree, "/foo/bar");
	assert(tmp);
	_dbus_object_tree_prune_node(leaf1);
	tmp = _dbus_object_tree_lookup(tree, "/foo/bar");
	assert(!tmp);
	tmp = _dbus_object_tree_lookup(tree, "/foo");
	assert(!tmp);

	tmp = _dbus_object_tree_lookup(tree, "/");
	assert(tmp);

	_dbus_object_tree_free(tree);
}

static void setup_dummy_interface(struct l_dbus_interface *iface)
{
}

static void interface_destroy(void *data)
{
	bool *destroyed = data;

	*destroyed = true;
}

static void test_dbus_object_tree_2(const void *test_data)
{
	struct _dbus_object_tree *tree;
	bool destroyed[2] = { false, false };

	tree = _dbus_object_tree_new();
	assert(tree);

	assert(_dbus_object_tree_new_object(tree, "/foo", NULL, NULL));
	assert(_dbus_object_tree_new_object(tree, "/foo/bar/baz", NULL, NULL));

	assert(_dbus_object_tree_lookup(tree, "/foo"));
	assert(_dbus_object_tree_lookup(tree, "/foo/bar"));
	assert(_dbus_object_tree_lookup(tree, "/foo/bar/baz"));

	assert(_dbus_object_tree_register_interface(tree, "org.example",
						setup_dummy_interface,
						interface_destroy, false));

	assert(_dbus_object_tree_add_interface(tree, "/foo",
						"org.example", &destroyed[0]));
	assert(!_dbus_object_tree_add_interface(tree, "/foo",
						"org.other", NULL));
	assert(_dbus_object_tree_add_interface(tree, "/foo/bar/baz",
						"org.example", &destroyed[1]));

	assert(!_dbus_object_tree_remove_interface(tree, "/foo", "org.other"));
	assert(_dbus_object_tree_remove_interface(tree, "/foo", "org.example"));
	assert(destroyed[0]);

	assert(_dbus_object_tree_object_destroy(tree, "/foo"));
	assert(!_dbus_object_tree_object_destroy(tree, "/foo/bar"));

	assert(_dbus_object_tree_lookup(tree, "/foo"));
	assert(_dbus_object_tree_lookup(tree, "/foo/bar"));
	assert(_dbus_object_tree_lookup(tree, "/foo/bar/baz"));

	destroyed[0] = false;
	assert(_dbus_object_tree_add_interface(tree, "/foo",
						"org.example", &destroyed[0]));

	assert(_dbus_object_tree_object_destroy(tree, "/foo/bar/baz"));

	assert(_dbus_object_tree_lookup(tree, "/foo"));
	assert(!_dbus_object_tree_lookup(tree, "/foo/bar"));
	assert(!_dbus_object_tree_lookup(tree, "/foo/bar/baz"));

	assert(_dbus_object_tree_object_destroy(tree, "/foo"));
	assert(destroyed[0] && destroyed[1]);
	assert(!_dbus_object_tree_lookup(tree, "/foo"));

	destroyed[0] = false;
	assert(_dbus_object_tree_add_interface(tree, "/foo",
						"org.example", &destroyed[0]));

	assert(!_dbus_object_tree_unregister_interface(tree, "org.other"));
	assert(_dbus_object_tree_unregister_interface(tree, "org.example"));
	assert(destroyed[0]);

	_dbus_object_tree_free(tree);
}

#define TEST_3_OBJ_COUNT 20000
static void test_dbus_object_tree_3(const void *test_data)
{
	struct _dbus_object_tree *tree;
	char path[50];
	struct l_hashmap *paths;
	unsigned int count = 0;
	struct l_dbus_message *message, *reply;
	struct l_dbus_message_iter objects, interfaces;
	const char *obj_path;

	tree = _dbus_object_tree_new();
	assert(tree);

	assert(_dbus_object_tree_register_interface(tree, "org.example",
						setup_dummy_interface,
						NULL, false));

	srand48(50);
	paths = l_hashmap_string_new();
	while (count < TEST_3_OBJ_COUNT) {
		unsigned int len = 0;
		unsigned int subpath_len = 0;
		bool repeat;

		/* Generate a random legal path composed of a, b and / chars */
		path[len++] = '/';

		while (len < sizeof(path) - 1) {
			const char *allowed;
			char ch;

			if (subpath_len)
				allowed = "aabb/E";
			else /* At least one letter required after a / */
				allowed = "ab";

			ch = allowed[lrand48() % strlen(allowed)];

			if (ch == 'E')
				break;
			else if (ch == '/')
				subpath_len = 0;
			else
				subpath_len++;

			path[len++] = ch;
		}

		/* Last character can't be a / */
		if (path[len - 1] == '/')
			len--;
		path[len] = '\0';

		repeat = l_hashmap_lookup(paths, path) != NULL;

		assert(_dbus_object_tree_add_interface(tree, path,
					"org.example", NULL) == !repeat);

		if (!repeat) {
			l_hashmap_insert(paths, path, path);
			count++;
		}
	}

	assert(_dbus_object_tree_add_interface(tree, "/",
					L_DBUS_INTERFACE_OBJECT_MANAGER, NULL));
	l_hashmap_insert(paths, "/", path);

	message = _dbus_message_new_method_call(1, "org.example", "/",
						L_DBUS_INTERFACE_OBJECT_MANAGER,
						"GetManagedObjects");
	l_dbus_message_set_arguments(message, "");
	_dbus_message_set_serial(message, 0);

	reply = _dbus_object_tree_get_objects(tree, NULL, "/", message);
	assert(reply);
	assert(!l_dbus_message_get_error(reply, NULL, NULL));
	assert(l_dbus_message_get_arguments(reply, "a{oa{sa{sv}}}", &objects));

	while (l_dbus_message_iter_next_entry(&objects, &obj_path, &interfaces))
		assert(l_hashmap_remove(paths, obj_path));

	l_dbus_message_unref(message);
	l_dbus_message_unref(reply);

	assert(l_hashmap_isempty(paths));
	l_hashmap_destroy(paths, NULL);

	assert(_dbus_object_tree_remove_interface(tree, "/",
					L_DBUS_INTERFACE_OBJECT_MANAGER));

	assert(_dbus_object_tree_unregister_interface(tree, "org.example"));
	_dbus_object_tree_free(tree);
}

static struct l_dbus_message *get_modems_callback(struct l_dbus *dbus,
					struct l_dbus_message *message,
					void *user_data)
{
	assert(user_data == dummy_data);
	callback_called = true;

	return NULL;
}

static void build_manager_interface(struct l_dbus_interface *iface)
{
	l_dbus_interface_method(iface, "GetModems", 0, get_modems_callback,
				"a(oa{sv})", "", "modems");
	l_dbus_interface_signal(iface, "ModemAdded", 0,
				"oa{sv}", "path", "properties");
	l_dbus_interface_signal(iface, "ModemRemoved", 0,
				"o", "path");
}

static const char *ofono_manager_introspection =
	"<!DOCTYPE node PUBLIC \""
	"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
	"\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
	"<node>\n"
	"\t<interface name=\"org.freedesktop.DBus.Introspectable\">\n"
	"\t\t<method name=\"Introspect\">\n"
	"\t\t\t<arg name=\"xml\" type=\"s\" direction=\"out\"/>\n"
	"\t\t</method>\n\t</interface>\n"
	"\t<interface name=\"org.ofono.Manager\">\n"
	"\t\t<method name=\"GetModems\">\n"
	"\t\t\t<arg name=\"modems\" type=\"a(oa{sv})\" direction=\"out\"/>\n"
	"\t\t</method>\n"
	"\t\t<signal name=\"ModemAdded\">\n"
	"\t\t\t<arg name=\"path\" type=\"o\"/>\n"
	"\t\t\t<arg name=\"properties\" type=\"a{sv}\"/>\n"
	"\t\t</signal>\n"
	"\t\t<signal name=\"ModemRemoved\">\n"						"\t\t\t<arg name=\"path\" type=\"o\"/>\n"
	"\t\t</signal>\n\t</interface>\n"
	"\t<node name=\"phonesim\"/>\n"
	"</node>\n";

static void test_dbus_object_tree_introspection(const void *test_data)
{
	struct _dbus_object_tree *tree;
	struct l_string *buf;
	char *xml;

	tree = _dbus_object_tree_new();

	_dbus_object_tree_register_interface(tree, "org.ofono.Manager",
						build_manager_interface,
						NULL, false);
	_dbus_object_tree_add_interface(tree, "/", "org.ofono.Manager", NULL);

	_dbus_object_tree_makepath(tree, "/phonesim");

	buf = l_string_new(1024);
	_dbus_object_tree_introspect(tree, "/", buf);
	xml = l_string_unwrap(buf);
	assert(!strcmp(ofono_manager_introspection, xml));
	l_free(xml);

	_dbus_object_tree_free(tree);
}

static void test_dbus_object_tree_dispatch(const void *test_data)
{
	struct _dbus_object_tree *tree;
	struct l_dbus_message *message;

	tree = _dbus_object_tree_new();

	_dbus_object_tree_register_interface(tree, "org.ofono.Manager",
						build_manager_interface,
						NULL, false);
	_dbus_object_tree_add_interface(tree, "/", "org.ofono.Manager",
					dummy_data);

	message = _dbus_message_new_method_call(1, "org.ofono", "/",
						"org.ofono.Manager",
						"GetModems");
	l_dbus_message_set_arguments(message, "");

	_dbus_object_tree_dispatch(tree, NULL, message);
	assert(callback_called);

	l_dbus_message_unref(message);

	_dbus_object_tree_free(tree);
}

static bool test_property_getter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_builder *builder,
					void *if_user_data)
{
	return true;
}

static struct l_dbus_message *test_property_setter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	return NULL;
}

int main(int argc, char *argv[])
{
	int ret;

	interface = _dbus_interface_new("org.freedesktop.SampleInterface");

	l_test_init(&argc, &argv);

	l_dbus_interface_method(interface, "Frobate",
				L_DBUS_METHOD_FLAG_DEPRECATED,
				NULL, "sa{us}", "i", "bar", "baz", "foo");
	l_dbus_interface_method(interface, "Bazify", 0, NULL, "v", "(iiu)",
				"bar", "bar");
	l_dbus_interface_method(interface, "Mogrify", 0, NULL, "",
				"(iiav)", "bar");

	l_dbus_interface_signal(interface, "Changed", 0, "b", "new_value");

	l_dbus_interface_property(interface, "Bar", 0, "y",
					test_property_getter,
					test_property_setter);

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

	l_test_add("_dbus_object_tree Sanity Tests 1",
					test_dbus_object_tree_1, NULL);

	l_test_add("_dbus_object_tree Sanity Tests 2",
					test_dbus_object_tree_2, NULL);

	l_test_add("_dbus_object_tree Sanity Tests 3",
					test_dbus_object_tree_3, NULL);

	l_test_add("_dbus_object_tree Introspection",
					test_dbus_object_tree_introspection,
					NULL);

	l_test_add("_dbus_object_tree Dispatcher",
					test_dbus_object_tree_dispatch,
					NULL);

	ret = l_test_run();

	_dbus_interface_free(interface);

	return ret;
}
