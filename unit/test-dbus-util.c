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

#include <assert.h>

#include <ell/ell.h>
#include "ell/dbus-private.h"

struct signature_test {
	bool valid;
	const char *signature;
};

#define SIGNATURE_TEST(v, sig, i)				\
	static struct signature_test sig_test##i = {		\
		.valid = v,					\
		.signature = sig,				\
	}

SIGNATURE_TEST(false, "a", 1);
SIGNATURE_TEST(false, "a{vs}", 2);
SIGNATURE_TEST(true, "(ss)", 3);
SIGNATURE_TEST(true, "(s(ss))", 4);
SIGNATURE_TEST(true, "as", 5);
SIGNATURE_TEST(true, "ab", 6);
SIGNATURE_TEST(true, "aas", 7);
SIGNATURE_TEST(true, "a(ss)", 8);
SIGNATURE_TEST(true, "asas", 9);
SIGNATURE_TEST(true, "av", 10);
SIGNATURE_TEST(true, "a{sv}", 11);
SIGNATURE_TEST(true, "v", 12);
SIGNATURE_TEST(true, "oa{sv}", 13);
SIGNATURE_TEST(true, "a(oa{sv})", 14);
SIGNATURE_TEST(true, "(sa{sv})sa{ss}us", 15);
SIGNATURE_TEST(true, "(bba{ss})", 16);

static void test_signature(const void *test_data)
{
	const struct signature_test *test = test_data;
	bool valid;

	valid = _dbus_valid_signature(test->signature);

	assert(valid == test->valid);
}

struct interface_test {
	bool valid;
	const char *interface;
};

#define INTERFACE_TEST(v, iface, i)				\
	static struct interface_test iface_test##i = {		\
		.valid = v,					\
		.interface = iface,				\
	}

INTERFACE_TEST(false, "org", 1);
INTERFACE_TEST(true, "org.foobar", 2);
INTERFACE_TEST(false, ".", 3);
INTERFACE_TEST(false, "org.", 4);
INTERFACE_TEST(false, "org.0bar", 5);
INTERFACE_TEST(false, "org.bar-", 6);
INTERFACE_TEST(true, "org.bar.baz", 7);
INTERFACE_TEST(false, "org.bar.", 8);
INTERFACE_TEST(true, "org.a.b.c", 9);

static void test_interface(const void *test_data)
{
	const struct interface_test *test = test_data;
	bool valid;

	valid = _dbus_valid_interface(test->interface);

	assert(valid == test->valid);
}

struct method_test {
	bool valid;
	const char *method;
};

#define METHOD_TEST(v, m, i)					\
	static struct method_test method_test##i = {		\
		.valid = v,					\
		.method = m,					\
	}

METHOD_TEST(false, "0Bar", 1);
METHOD_TEST(true, "Bar", 2);

static void test_method(const void *test_data)
{
	const struct method_test *test = test_data;
	bool valid;

	valid = _dbus_valid_method(test->method);

	assert(valid == test->valid);
}

struct bus_name_test {
	bool valid;
	const char *bus_name;
};

#define BUS_NAME_TEST(v, name, i)				\
	static struct bus_name_test bus_name_test##i = {	\
		.valid = v,					\
		.bus_name = name,				\
	}

BUS_NAME_TEST(false, "org", 1);
BUS_NAME_TEST(true, "org.foobar", 2);
BUS_NAME_TEST(false, ".", 3);
BUS_NAME_TEST(false, "0Bar", 4);
BUS_NAME_TEST(true, "org.foo-bar", 5);
BUS_NAME_TEST(false, ":1.2f", 6);
BUS_NAME_TEST(true, ":1.2", 7);

static void test_bus_name(const void *test_data)
{
	const struct bus_name_test *test = test_data;
	bool valid;

	valid = _dbus_valid_bus_name(test->bus_name);

	assert(valid == test->valid);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("Signature Test 1", test_signature, &sig_test1);
	l_test_add("Signature test 2", test_signature, &sig_test2);
	l_test_add("Signature test 3", test_signature, &sig_test3);
	l_test_add("Signature test 4", test_signature, &sig_test4);
	l_test_add("Signature test 5", test_signature, &sig_test5);
	l_test_add("Signature test 6", test_signature, &sig_test6);
	l_test_add("Signature test 7", test_signature, &sig_test7);
	l_test_add("Signature test 8", test_signature, &sig_test8);
	l_test_add("Signature test 9", test_signature, &sig_test9);
	l_test_add("Signature test 10", test_signature, &sig_test10);
	l_test_add("Signature test 11", test_signature, &sig_test11);
	l_test_add("Signature test 12", test_signature, &sig_test12);
	l_test_add("Signature test 13", test_signature, &sig_test13);
	l_test_add("Signature test 14", test_signature, &sig_test14);
	l_test_add("Signature test 15", test_signature, &sig_test15);
	l_test_add("Signature test 16", test_signature, &sig_test16);

	l_test_add("Interface Test 1", test_interface, &iface_test1);
	l_test_add("Interface Test 2", test_interface, &iface_test2);
	l_test_add("Interface Test 3", test_interface, &iface_test3);
	l_test_add("Interface Test 4", test_interface, &iface_test4);
	l_test_add("Interface Test 5", test_interface, &iface_test5);
	l_test_add("Interface Test 6", test_interface, &iface_test6);
	l_test_add("Interface Test 7", test_interface, &iface_test7);
	l_test_add("Interface Test 8", test_interface, &iface_test8);
	l_test_add("Interface Test 9", test_interface, &iface_test9);

	l_test_add("Method Test 1", test_method, &method_test1);
	l_test_add("Method Test 2", test_method, &method_test2);

	l_test_add("Bus Name Test 1", test_bus_name, &bus_name_test1);
	l_test_add("Bus Name Test 2", test_bus_name, &bus_name_test2);
	l_test_add("Bus Name Test 3", test_bus_name, &bus_name_test3);
	l_test_add("Bus Name Test 4", test_bus_name, &bus_name_test4);
	l_test_add("Bus Name Test 5", test_bus_name, &bus_name_test5);
	l_test_add("Bus Name Test 6", test_bus_name, &bus_name_test6);
	l_test_add("Bus Name Test 7", test_bus_name, &bus_name_test7);

	return l_test_run();
}
