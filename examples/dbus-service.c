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

static bool test_string_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct test_data *test = user_data;

	l_dbus_message_builder_append_basic(builder, 's', test->string);

	return true;
}

static void test_string_setter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_iter *new_value,
				l_dbus_property_complete_cb_t complete,
				void *user_data)
{
	const char *strvalue;
	struct test_data *test = user_data;

	if (!l_dbus_message_iter_get_variant(new_value, "s", &strvalue)) {
		complete(dbus, message, l_dbus_message_new_error(message,
					"org.test.InvalidArguments",
					"String value expected"));
		return;
	}

	l_info("New String value: %s", strvalue);
	l_free(test->string);
	test->string = l_strdup(strvalue);

	complete(dbus, message, NULL);
}

static bool test_int_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	struct test_data *test = user_data;

	l_dbus_message_builder_append_basic(builder, 'u', &test->integer);

	return true;
}

static void test_int_setter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_iter *new_value,
				l_dbus_property_complete_cb_t complete,
				void *user_data)
{
	uint32_t u;
	struct test_data *test = user_data;

	if (!l_dbus_message_iter_get_variant(new_value, "u", &u)) {
		complete(dbus, message, l_dbus_message_new_error(message,
					"org.test.InvalidArguments",
					"Integer value expected"));
		return;
	}

	l_info("New Integer value: %u", u);
	test->integer = u;

	complete(dbus, message, NULL);
}

static void setup_test_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "MethodCall", 0,
				test_method_call, "", "");

	l_dbus_interface_property(interface, "String", 0, "s",
					test_string_getter, test_string_setter);
	l_dbus_interface_property(interface, "Integer", 0, "u",
					test_int_getter, test_int_setter);
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

	if (!l_dbus_object_manager_enable(dbus)) {
		l_info("Unable to enable Object Manager");
		goto cleanup;
	}

	test = l_new(struct test_data, 1);
	test->string = l_strdup("Default");
	test->integer = 42;

	if (!l_dbus_register_interface(dbus, "org.test", setup_test_interface,
					test_data_destroy, true)) {
		l_info("Unable to register interface");
		test_data_destroy(test);
		goto cleanup;
	}

	if (!l_dbus_object_add_interface(dbus, "/test", "org.test", test)) {
		l_info("Unable to instantiate interface");
		test_data_destroy(test);
		goto cleanup;
	}

	if (!l_dbus_object_add_interface(dbus, "/test",
				"org.freedesktop.DBus.Properties", NULL)) {
		l_info("Unable to instantiate the properties interface");
		test_data_destroy(test);
		goto cleanup;
	}

	l_main_run();

	l_dbus_unregister_object(dbus, "/test");

cleanup:
	l_dbus_destroy(dbus);
	l_signal_remove(signal);

	return 0;
}
