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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>

#include <ell/ell.h>
#include <ell/dbus-service.h>

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

static void signal_handler(struct l_signal *signal, uint32_t signo,
							void *user_data)
{
	switch (signo) {
	case SIGINT:
	case SIGTERM:
		l_info("Terminate");
		l_main_quit();
		break;
	}
}

static void request_name_setup(struct l_dbus_message *message, void *user_data)
{
	const char *name = "org.test";

	l_dbus_message_set_arguments(message, "su", name, 0);
}

static void request_name_callback(struct l_dbus_message *message,
							void *user_data)
{
	const char *error, *text;
	uint32_t result;

	if (l_dbus_message_get_error(message, &error, &text)) {
		l_error("error=%s", error);
		l_error("message=%s", text);
		return;
	}

	if (!l_dbus_message_get_arguments(message, "u", &result))
		return;

	l_info("request name result=%d", result);
}

static void ready_callback(void *user_data)
{
	l_info("ready");
}

static void disconnect_callback(void *user_data)
{
	l_main_quit();
}

struct test_data {
	char *string;
	uint32_t integer;
};

static void test_data_destroy(void *data)
{
	struct test_data *test = data;

	l_free(test->string);
	l_free(test);
}

static struct l_dbus_message *test_set_property(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct test_data *test = user_data;
	struct l_dbus_message *reply;
	struct l_dbus_message *signal;
	struct l_dbus_message_iter variant;
	const char *property;

	if (!l_dbus_message_get_arguments(message, "sv", &property, &variant))
		return l_dbus_message_new_error(message,
						"org.test.InvalidArguments",
						"Invalid arguments");

	if (!strcmp(property, "String")) {
		const char *strvalue;

		if (!l_dbus_message_iter_get_variant(&variant, "s",
							&strvalue))
			return l_dbus_message_new_error(message,
						"org.test.InvalidArguments",
						"String value expected");

		l_info("New String value: %s", strvalue);
		l_free(test->string);
		test->string = l_strdup(strvalue);

		signal = l_dbus_message_new_signal(dbus, "/test",
					"org.test", "PropertyChanged");
		l_dbus_message_set_arguments(signal, "sv",
						"String", "s", test->string);
	} else if (!strcmp(property, "Integer")) {
		uint32_t u;

		if (!l_dbus_message_iter_get_variant(&variant, "u", &u))
			return l_dbus_message_new_error(message,
						"org.test.InvalidArguments",
						"Integer value expected");

		l_info("New Integer value: %u", u);
		test->integer = u;
		signal = l_dbus_message_new_signal(dbus, "/test",
					"org.test", "PropertyChanged");
		l_dbus_message_set_arguments(signal, "sv",
						"Integer", "u", test->integer);
	} else
		return l_dbus_message_new_error(message,
						"org.test.InvalidArguments",
						"Unknown Property %s",
						property);

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "");
	l_dbus_send(dbus, reply);

	l_dbus_send(dbus, signal);
	return NULL;
}

static struct l_dbus_message *test_get_properties(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct test_data *test = user_data;
	struct l_dbus_message *reply;

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "a{sv}", 2,
					"String", "s", test->string,
					"Integer", "u", test->integer);

	return reply;
}

static struct l_dbus_message *test_method_call(struct l_dbus *dbus,
						struct l_dbus_message *message,
						void *user_data)
{
	struct l_dbus_message *reply;

	l_info("Method Call");

	reply = l_dbus_message_new_method_return(message);
	l_dbus_message_set_arguments(reply, "");

	return reply;
}

static void setup_test_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "GetProperties", 0,
				test_get_properties,
				"a{sv}", "", "properties");
	l_dbus_interface_method(interface, "SetProperty", 0,
				test_set_property,
				"", "sv", "name", "value");
	l_dbus_interface_method(interface, "MethodCall", 0,
				test_method_call, "", "");

	l_dbus_interface_signal(interface, "PropertyChanged", 0,
				"sv", "name", "value");

	l_dbus_interface_rw_property(interface, "String", "s");
	l_dbus_interface_rw_property(interface, "Integer", "u");
}

int main(int argc, char *argv[])
{
	struct l_dbus *dbus;
	struct l_signal *signal;
	sigset_t mask;
	struct test_data *test;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	l_log_set_stderr();

	dbus = l_dbus_new_default(L_DBUS_SESSION_BUS);
	l_dbus_set_debug(dbus, do_debug, "[DBUS] ", NULL);
	l_dbus_set_ready_handler(dbus, ready_callback, dbus, NULL);
	l_dbus_set_disconnect_handler(dbus, disconnect_callback, NULL, NULL);

	l_dbus_method_call(dbus, "org.freedesktop.DBus",
				"/org/freedesktop/DBus",
				"org.freedesktop.DBus", "RequestName",
				request_name_setup,
				request_name_callback, NULL, NULL);

	test = l_new(struct test_data, 1);
	test->string = l_strdup("Default");
	test->integer = 42;

	if (!l_dbus_register_interface(dbus, "/test", "org.test",
					setup_test_interface, test,
					test_data_destroy)) {
		l_info("Unable to register interface");
		test_data_destroy(test);
		goto cleanup;
	}

	l_main_run();

	l_dbus_unregister_interface(dbus, "/test", "org.test");

cleanup:
	l_dbus_destroy(dbus);
	l_signal_remove(signal);

	return 0;
}
