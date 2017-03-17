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

#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <stdio.h>

#include <ell/ell.h>
#include <ell/dbus-private.h>

#define TEST_BUS_ADDRESS "unix:path=/tmp/ell-test-bus"

static pid_t dbus_daemon_pid = -1;

static char bus_address[128];

static bool start_dbus_daemon(void)
{
	char *prg_argv[6];
	char *prg_envp[1];
	pid_t pid;

	prg_argv[0] = "/usr/bin/dbus-daemon";
	prg_argv[1] = "--session";
	prg_argv[2] = "--address=" TEST_BUS_ADDRESS;
	prg_argv[3] = "--nopidfile";
	prg_argv[4] = "--nofork";
	prg_argv[5] = NULL;

	prg_envp[0] = NULL;

	l_info("launching dbus-daemon");

	pid = fork();
	if (pid < 0) {
		l_error("failed to fork new process");
		return false;
	}

	if (pid == 0) {
		execve(prg_argv[0], prg_argv, prg_envp);
		exit(EXIT_SUCCESS);
	}

	l_info("dbus-daemon process %d created", pid);

	dbus_daemon_pid = pid;

	strcpy(bus_address, TEST_BUS_ADDRESS);

	return true;
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
	case SIGCHLD:
		while (1) {
			pid_t pid;
			int status;

			pid = waitpid(WAIT_ANY, &status, WNOHANG);
			if (pid < 0 || pid == 0)
				break;

			l_info("process %d terminated with status=%d\n",
								pid, status);

			if (pid == dbus_daemon_pid) {
				dbus_daemon_pid = -1;
				l_main_quit();
			}
		}
		break;
	}
}

static struct l_dbus *dbus;

struct dbus_test {
	const char *name;
	void (*start)(struct l_dbus *dbus, void *);
	void *data;
};

static bool success;
static struct l_queue *tests;
static const struct l_queue_entry *current;

static void test_add(const char *name,
			void (*start)(struct l_dbus *dbus, void *),
			void *test_data)
{
	struct dbus_test *test = l_new(struct dbus_test, 1);

	test->name = name;
	test->start = start;
	test->data = test_data;

	if (!tests)
		tests = l_queue_new();

	l_queue_push_tail(tests, test);
}

static void test_next()
{
	struct dbus_test *test;

	if (current)
		current = current->next;
	else
		current = l_queue_get_entries(tests);

	if (!current) {
		success = true;
		l_main_quit();
		return;
	}

	test = current->data;

	l_info("TEST: %s", test->name);

	test->start(dbus, test->data);
}

#define test_assert(cond)	\
	do {	\
		if (!(cond)) {	\
			l_info("TEST FAILED in %s at %s:%i: %s",	\
				__func__, __FILE__, __LINE__,	\
				L_STRINGIFY(cond));	\
			l_main_quit();	\
			return;	\
		}	\
	} while (0)

static void request_name_callback(struct l_dbus *dbus, bool success,
					bool queued, void *user_data)
{
	l_info("request name result=%s",
		success ? (queued ? "queued" : "success") : "failed");

	test_next();
}

static void ready_callback(void *user_data)
{
	l_info("ready");

	l_dbus_name_acquire(dbus, "org.test", false, false, false,
				request_name_callback, NULL);
}

static void disconnect_callback(void *user_data)
{
	l_info("Disconnected from DBus");
	l_main_quit();
}

static bool test_string_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	return l_dbus_message_builder_append_basic(builder, 's', "foo");
}

static bool setter_called;
static bool int_optional;

static struct l_dbus_message *test_string_setter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	const char *strvalue;

	if (!l_dbus_message_iter_get_variant(new_value, "s", &strvalue))
		goto done;

	if (strcmp(strvalue, "bar"))
		goto done;

	setter_called = true;

done:
	complete(dbus, message, NULL);

	return NULL;
}

static bool test_int_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	uint32_t u;

	if (int_optional)
		return false;

	u = 5;

	return l_dbus_message_builder_append_basic(builder, 'u', &u);
}

static struct l_dbus_message *test_int_setter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	uint32_t u;

	if (!l_dbus_message_iter_get_variant(new_value, "u", &u))
		goto done;

	if (u != 42)
		goto done;

	setter_called = true;

done:
	return l_dbus_message_new_method_return(message);
}

static struct l_dbus_message *test_error_setter(struct l_dbus *dbus,
					struct l_dbus_message *message,
					struct l_dbus_message_iter *new_value,
					l_dbus_property_complete_cb_t complete,
					void *user_data)
{
	setter_called = true;

	return l_dbus_message_new_error(message, "org.test.Error", "Error");
}

static bool test_path_getter(struct l_dbus *dbus,
				struct l_dbus_message *message,
				struct l_dbus_message_builder *builder,
				void *user_data)
{
	return l_dbus_message_builder_append_basic(builder, 'o', "/foo/bar");
}

static void setup_test_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_property(interface, "String", 0, "s",
					test_string_getter, test_string_setter);
	l_dbus_interface_property(interface, "Integer", 0, "u",
					test_int_getter, test_int_setter);
	l_dbus_interface_property(interface, "Readonly", 0, "s",
					test_string_getter, NULL);
	l_dbus_interface_property(interface, "SetError", 0, "s",
					test_string_getter, test_error_setter);
	l_dbus_interface_property(interface, "Path", 0, "o",
					test_path_getter, NULL);
}

static void validate_properties(struct l_dbus_message_iter *dict)
{
	struct l_dbus_message_iter variant;
	const char *name, *strval;
	uint32_t intval;

	test_assert(l_dbus_message_iter_next_entry(dict, &name, &variant));
	test_assert(!strcmp(name, "String"));
	test_assert(l_dbus_message_iter_get_variant(&variant, "s", &strval));
	test_assert(!strcmp(strval, "foo"));

	if (!int_optional) {
		test_assert(l_dbus_message_iter_next_entry(dict, &name,
								&variant));
		test_assert(!strcmp(name, "Integer"));
		test_assert(l_dbus_message_iter_get_variant(&variant, "u",
								&intval));
		test_assert(intval == 5);
	}

	test_assert(l_dbus_message_iter_next_entry(dict, &name, &variant));
	test_assert(!strcmp(name, "Readonly"));
	test_assert(l_dbus_message_iter_get_variant(&variant, "s", &strval));
	test_assert(!strcmp(strval, "foo"));

	test_assert(l_dbus_message_iter_next_entry(dict, &name, &variant));
	test_assert(!strcmp(name, "SetError"));
	test_assert(l_dbus_message_iter_get_variant(&variant, "s", &strval));
	test_assert(!strcmp(strval, "foo"));

	test_assert(l_dbus_message_iter_next_entry(dict, &name, &variant));
	test_assert(!strcmp(name, "Path"));
	test_assert(l_dbus_message_iter_get_variant(&variant, "o", &strval));
	test_assert(!strcmp(strval, "/foo/bar"));

	test_assert(!l_dbus_message_iter_next_entry(dict, &name, &variant));
}

static void get_properties_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message_iter dict;

	test_assert(!l_dbus_message_get_error(message, NULL, NULL));
	test_assert(l_dbus_message_get_arguments(message, "a{sv}", &dict));

	validate_properties(&dict);

	test_next();
}

static void test_old_get(struct l_dbus *dbus, void *test_data)
{
	struct l_dbus_message *call =
		l_dbus_message_new_method_call(dbus, "org.test", "/test",
						"org.test", "GetProperties");

	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, ""));

	test_assert(l_dbus_send_with_reply(dbus, call, get_properties_callback,
						NULL, NULL));
}

static void test_old_optional_get(struct l_dbus *dbus, void *test_data)
{
	struct l_dbus_message *call =
		l_dbus_message_new_method_call(dbus, "org.test", "/test",
						"org.test", "GetProperties");

	int_optional = true;

	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, ""));

	test_assert(l_dbus_send_with_reply(dbus, call, get_properties_callback,
						NULL, NULL));
}
static void set_invalid_callback(struct l_dbus_message *message,
					void *user_data)
{
	test_assert(l_dbus_message_get_error(message, NULL, NULL));
	test_assert(!setter_called);

	test_next();
}

static void old_set_error_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	test_assert(l_dbus_message_get_error(message, NULL, NULL));
	test_assert(setter_called);
	setter_called = false;

	call = l_dbus_message_new_method_call(dbus, "org.test", "/test",
						"org.test", "SetProperty");
	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, "sv", "Invalid",
							"s", "bar"));

	test_assert(l_dbus_send_with_reply(dbus, call, set_invalid_callback,
						NULL, NULL));
}

static void old_set_ro_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	test_assert(l_dbus_message_get_error(message, NULL, NULL));
	test_assert(!setter_called);

	call = l_dbus_message_new_method_call(dbus, "org.test", "/test",
						"org.test", "SetProperty");
	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, "sv", "SetError",
							"s", "bar"));

	test_assert(l_dbus_send_with_reply(dbus, call, old_set_error_callback,
						NULL, NULL));
}

static void old_set_int_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	test_assert(!l_dbus_message_get_error(message, NULL, NULL));
	test_assert(l_dbus_message_get_arguments(message, ""));
	test_assert(setter_called);
	setter_called = false;

	call = l_dbus_message_new_method_call(dbus, "org.test", "/test",
						"org.test", "SetProperty");
	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, "sv", "Readonly",
							"s", "bar"));

	test_assert(l_dbus_send_with_reply(dbus, call, old_set_ro_callback,
						NULL, NULL));
}

static void old_set_string_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	test_assert(!l_dbus_message_get_error(message, NULL, NULL));
	test_assert(l_dbus_message_get_arguments(message, ""));
	test_assert(setter_called);
	setter_called = false;

	call = l_dbus_message_new_method_call(dbus, "org.test", "/test",
						"org.test", "SetProperty");
	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, "sv", "Integer",
							"u", 42));

	test_assert(l_dbus_send_with_reply(dbus, call, old_set_int_callback,
						NULL, NULL));
}

static void test_old_set(struct l_dbus *dbus, void *test_data)
{
	struct l_dbus_message *call =
		l_dbus_message_new_method_call(dbus, "org.test", "/test",
						"org.test", "SetProperty");

	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, "sv", "String",
							"s", "bar"));

	test_assert(!setter_called);
	test_assert(l_dbus_send_with_reply(dbus, call, old_set_string_callback,
						NULL, NULL));
}

static void new_get_invalid_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	test_assert(l_dbus_message_get_error(message, NULL, NULL));

	call = l_dbus_message_new_method_call(dbus, "org.test", "/test",
					"org.freedesktop.DBus.Properties",
					"GetAll");
	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, "s", "org.test"));

	test_assert(l_dbus_send_with_reply(dbus, call, get_properties_callback,
						NULL, NULL));
}

static void new_get_bad_if_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	test_assert(l_dbus_message_get_error(message, NULL, NULL));

	call = l_dbus_message_new_method_call(dbus, "org.test", "/test",
					"org.freedesktop.DBus.Properties",
					"Get");
	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, "ss",
							"org.test", "Invalid"));

	test_assert(l_dbus_send_with_reply(dbus, call, new_get_invalid_callback,
						NULL, NULL));
}

static void new_get_callback(struct l_dbus_message *message, void *user_data)
{
	struct l_dbus_message_iter variant;
	const char *strval;
	struct l_dbus_message *call;

	test_assert(!l_dbus_message_get_error(message, NULL, NULL));
	test_assert(l_dbus_message_get_arguments(message, "v", &variant));
	test_assert(l_dbus_message_iter_get_variant(&variant, "s", &strval));
	test_assert(!strcmp(strval, "foo"));

	call = l_dbus_message_new_method_call(dbus, "org.test", "/test",
					"org.freedesktop.DBus.Properties",
					"Get");
	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, "ss", "org.invalid",
							"String"));

	test_assert(l_dbus_send_with_reply(dbus, call, new_get_bad_if_callback,
						NULL, NULL));
}

static void test_new_get(struct l_dbus *dbus, void *test_data)
{
	struct l_dbus_message *call =
		l_dbus_message_new_method_call(dbus, "org.test", "/test",
					"org.freedesktop.DBus.Properties",
					"Get");

	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, "ss",
							"org.test", "String"));

	test_assert(l_dbus_send_with_reply(dbus, call, new_get_callback,
						NULL, NULL));
}

static void new_set_bad_if_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	test_assert(l_dbus_message_get_error(message, NULL, NULL));
	test_assert(!setter_called);

	call = l_dbus_message_new_method_call(dbus, "org.test", "/test",
					"org.freedesktop.DBus.Properties",
					"Set");
	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, "ssv", "org.test",
							"Invalid", "s", "bar"));

	test_assert(l_dbus_send_with_reply(dbus, call, set_invalid_callback,
						NULL, NULL));
}

static void new_set_error_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	test_assert(l_dbus_message_get_error(message, NULL, NULL));
	test_assert(setter_called);
	setter_called = false;

	call = l_dbus_message_new_method_call(dbus, "org.test", "/test",
					"org.freedesktop.DBus.Properties",
					"Set");
	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, "ssv", "org.invalid",
							"String", "s", "bar"));

	test_assert(l_dbus_send_with_reply(dbus, call, new_set_bad_if_callback,
						NULL, NULL));
}

static void new_set_ro_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	test_assert(l_dbus_message_get_error(message, NULL, NULL));
	test_assert(!setter_called);

	call = l_dbus_message_new_method_call(dbus, "org.test", "/test",
					"org.freedesktop.DBus.Properties",
					"Set");
	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, "ssv", "org.test",
							"SetError",
							"s", "bar"));

	test_assert(l_dbus_send_with_reply(dbus, call, new_set_error_callback,
						NULL, NULL));
}

static void new_set_int_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	test_assert(!l_dbus_message_get_error(message, NULL, NULL));
	test_assert(l_dbus_message_get_arguments(message, ""));
	test_assert(setter_called);
	setter_called = false;

	call = l_dbus_message_new_method_call(dbus, "org.test", "/test",
					"org.freedesktop.DBus.Properties",
					"Set");
	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, "ssv", "org.test",
							"Readonly",
							"s", "bar"));

	test_assert(l_dbus_send_with_reply(dbus, call, new_set_ro_callback,
						NULL, NULL));
}

static void new_set_string_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message *call;

	test_assert(!l_dbus_message_get_error(message, NULL, NULL));
	test_assert(l_dbus_message_get_arguments(message, ""));
	test_assert(setter_called);
	setter_called = false;

	call = l_dbus_message_new_method_call(dbus, "org.test", "/test",
					"org.freedesktop.DBus.Properties",
					"Set");
	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, "ssv", "org.test",
							"Integer", "u", 42));

	test_assert(l_dbus_send_with_reply(dbus, call, new_set_int_callback,
						NULL, NULL));
}

static void test_new_set(struct l_dbus *dbus, void *test_data)
{
	struct l_dbus_message *call =
		l_dbus_message_new_method_call(dbus, "org.test", "/test",
					"org.freedesktop.DBus.Properties",
					"Set");

	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, "ssv", "org.test",
							"String", "s", "bar"));

	test_assert(!setter_called);
	test_assert(l_dbus_send_with_reply(dbus, call, new_set_string_callback,
						NULL, NULL));
}

static struct l_timeout *signal_timeout;

static void signal_timeout_callback(struct l_timeout *timeout, void *user_data)
{
	signal_timeout = NULL;
	test_assert(false);
}

static bool old_signal_received, new_signal_received;
static bool signal_success;

static void test_check_signal_success(void)
{
	struct l_dbus_message *call;

	if (!old_signal_received || !new_signal_received)
		return;

	l_timeout_remove(signal_timeout);
	signal_timeout = NULL;

	if (!signal_success) {
		signal_success = true;

		/* Now repeat the test for the signal triggered by Set */

		old_signal_received = false;
		new_signal_received = false;

		signal_timeout = l_timeout_create(1, signal_timeout_callback,
							NULL, NULL);
		test_assert(signal_timeout);

		call = l_dbus_message_new_method_call(dbus, "org.test", "/test",
					"org.freedesktop.DBus.Properties",
					"Set");
		test_assert(call);
		test_assert(l_dbus_message_set_arguments(call, "ssv",
							"org.test", "String",
							"s", "bar"));

		test_assert(!setter_called);
		test_assert(l_dbus_send(dbus, call));
	} else {
		test_assert(setter_called);
		setter_called = false;

		test_next();
	}
}

static void test_old_signal_callback(struct l_dbus_message *message,
					void *user_data)
{
	const char *property, *value;
	struct l_dbus_message_iter variant;

	if (!signal_timeout)
		return;

	test_assert(l_dbus_message_get_arguments(message, "sv",
							&property, &variant));
	test_assert(!strcmp(property, "String"));
	test_assert(l_dbus_message_iter_get_variant(&variant, "s", &value));
	test_assert(!strcmp(value, "foo"));

	test_assert(!old_signal_received);
	old_signal_received = true;

	test_check_signal_success();
}

static void test_new_signal_callback(struct l_dbus_message *message,
					void *user_data)
{
	const char *interface, *property, *value;
	struct l_dbus_message_iter variant, changed, invalidated;

	if (!signal_timeout)
		return;

	test_assert(l_dbus_message_get_arguments(message, "sa{sv}as",
							&interface, &changed,
							&invalidated));

	test_assert(l_dbus_message_iter_next_entry(&changed, &property,
							&variant));
	test_assert(!strcmp(property, "String"));
	test_assert(l_dbus_message_iter_get_variant(&variant, "s", &value));
	test_assert(!strcmp(value, "foo"));

	test_assert(!l_dbus_message_iter_next_entry(&changed, &property,
							&variant));
	test_assert(!l_dbus_message_iter_next_entry(&invalidated,
							&property));

	test_assert(!new_signal_received);
	new_signal_received = true;

	test_check_signal_success();
}

static void test_property_signals(struct l_dbus *dbus, void *test_data)
{
	old_signal_received = false;
	new_signal_received = false;

	signal_timeout = l_timeout_create(1, signal_timeout_callback,
						NULL, NULL);
	test_assert(signal_timeout);

	test_assert(l_dbus_property_changed(dbus, "/test",
						"org.test", "String"));
}

static void object_manager_callback(struct l_dbus_message *message,
					void *user_data)
{
	struct l_dbus_message_iter objects, interfaces, properties, variant;
	const char *path, *interface, *name;
	bool object_manager_found = false;
	bool test_found = false;
	bool properties_found = false;

	test_assert(!l_dbus_message_get_error(message, NULL, NULL));
	test_assert(l_dbus_message_get_arguments(message, "a{oa{sa{sv}}}",
							&objects));

	while (l_dbus_message_iter_next_entry(&objects, &path, &interfaces)) {
		while (l_dbus_message_iter_next_entry(&interfaces, &interface,
							&properties)) {
			if (!strcmp(path, "/") && !strcmp(interface,
					"org.freedesktop.DBus.ObjectManager")) {
				test_assert(!object_manager_found);
				object_manager_found = true;
				test_assert(!l_dbus_message_iter_next_entry(
							&properties, &name,
							&variant));
			}

			if (!strcmp(path, "/test") && !strcmp(interface,
					"org.freedesktop.DBus.Properties")) {
				test_assert(!properties_found);
				properties_found = true;
				test_assert(!l_dbus_message_iter_next_entry(
							&properties, &name,
							&variant));
			}

			if (!strcmp(path, "/test") && !strcmp(interface,
								"org.test")) {
				test_assert(!test_found);
				test_found = true;
				validate_properties(&properties);
			}
		}
	}

	test_assert(object_manager_found && test_found && properties_found);

	test_next();
}

static void test_object_manager_get(struct l_dbus *dbus, void *test_data)
{
	struct l_dbus_message *call =
		l_dbus_message_new_method_call(dbus, "org.test", "/",
					"org.freedesktop.DBus.ObjectManager",
					"GetManagedObjects");

	test_assert(call);
	test_assert(l_dbus_message_set_arguments(call, ""));

	test_assert(l_dbus_send_with_reply(dbus, call, object_manager_callback,
						NULL, NULL));
}

static struct l_timeout *om_signal_timeout;

static void om_signal_timeout_callback(struct l_timeout *timeout,
					void *user_data)
{
	om_signal_timeout = NULL;
	test_assert(false);
}

static bool expect_interfaces_added;

static void om_signal_callback(struct l_dbus_message *message, void *user_data)
{
	const char *path, *interface, *member;
	struct l_dbus_message_iter interfaces, properties;

	if (!om_signal_timeout)
		return;

	member = l_dbus_message_get_member(message);

	if (!strcmp(member, "InterfacesAdded"))
		test_assert(expect_interfaces_added);
	else if (!strcmp(member, "InterfacesRemoved"))
		test_assert(!expect_interfaces_added);
	else
		return;

	if (!strcmp(member, "InterfacesAdded")) {
		test_assert(l_dbus_message_get_arguments(message, "oa{sa{sv}}",
								&path,
								&interfaces));
		test_assert(!strcmp(path, "/test2"));

		test_assert(l_dbus_message_iter_next_entry(&interfaces,
								&interface,
								&properties));
		test_assert(!strcmp(interface, "org.test"));
		validate_properties(&properties);

		test_assert(!l_dbus_message_iter_next_entry(&interfaces,
								&interface,
								&properties));

		/* Now repeat the test for the InterfacesRemoved signal */

		expect_interfaces_added = false;
		test_assert(l_dbus_unregister_object(dbus, "/test2"));
	} else {
		test_assert(l_dbus_message_get_arguments(message, "oas",
								&path,
								&interfaces));
		test_assert(!strcmp(path, "/test2"));

		test_assert(l_dbus_message_iter_next_entry(&interfaces,
								&interface));
		test_assert(!strcmp(interface, "org.test"));

		test_assert(!l_dbus_message_iter_next_entry(&interfaces,
								&interface));

		l_timeout_remove(om_signal_timeout);
		om_signal_timeout = NULL;

		test_next();
	}
}

static void test_object_manager_signals(struct l_dbus *dbus, void *test_data)
{
	om_signal_timeout = l_timeout_create(1, om_signal_timeout_callback,
						NULL, NULL);
	test_assert(om_signal_timeout);

	expect_interfaces_added = true;
	test_assert(l_dbus_object_add_interface(dbus, "/test2", "org.test",
						NULL));
}

static void test_run(void)
{
	success = false;

	l_dbus_set_ready_handler(dbus, ready_callback, dbus, NULL);
	l_dbus_set_disconnect_handler(dbus, disconnect_callback, NULL, NULL);

	if (!l_dbus_register_interface(dbus, "org.test", setup_test_interface,
					NULL, true)) {
		l_info("Unable to register interface");
		return;
	}

	if (!l_dbus_object_add_interface(dbus, "/test", "org.test", NULL)) {
		l_info("Unable to instantiate interface");
		return;
	}

	if (!l_dbus_object_add_interface(dbus, "/test",
				"org.freedesktop.DBus.Properties", NULL)) {
		l_info("Unable to instantiate the properties interface");
		return;
	}

	l_dbus_add_signal_watch(dbus, "org.test", "/test", "org.test",
				"PropertyChanged", L_DBUS_MATCH_NONE,
				test_old_signal_callback, NULL);
	l_dbus_add_signal_watch(dbus, "org.test", "/test",
				"org.freedesktop.DBus.Properties",
				"PropertiesChanged", L_DBUS_MATCH_ARGUMENT(0),
				"org.test", L_DBUS_MATCH_NONE,
				test_new_signal_callback, NULL);

	if (!l_dbus_object_manager_enable(dbus)) {
		l_info("Unable to enable Object Manager");
		return;
	}

	l_dbus_add_signal_watch(dbus, "org.test", "/",
				"org.freedesktop.DBus.ObjectManager",
				NULL, L_DBUS_MATCH_NONE,
				om_signal_callback, NULL);

	l_main_run();
}

int main(int argc, char *argv[])
{
	struct l_signal *signal;
	sigset_t mask;
	int i;

	if (!l_main_init())
		return -1;

	test_add("Legacy properties get", test_old_get, NULL);
	test_add("Legacy properties set", test_old_set, NULL);
	test_add("Legacy optional property", test_old_optional_get, NULL);
	test_add("org.freedesktop.DBus.Properties get", test_new_get, NULL);
	test_add("org.freedesktop.DBus.Properties set", test_new_set, NULL);
	test_add("Property changed signals", test_property_signals, NULL);
	test_add("org.freedesktop.DBus.ObjectManager get",
			test_object_manager_get, NULL);
	test_add("org.freedesktop.DBus.ObjectManager signals",
			test_object_manager_signals, NULL);

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGCHLD);

	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	l_log_set_stderr();

	if (!start_dbus_daemon())
		return -1;

	for (i = 0; i < 10; i++) {
		usleep(200 * 1000);

		dbus = l_dbus_new(bus_address);
		if (dbus)
			break;
	}

	test_run();

	l_dbus_destroy(dbus);

	kill(dbus_daemon_pid, SIGKILL);

	if (!success)
		goto done;

	dbus = l_dbus_new(bus_address);

	test_run();

	l_dbus_destroy(dbus);

done:
	l_signal_remove(signal);

	l_queue_destroy(tests, l_free);

	l_main_exit();

	if (!success)
		abort();

	return 0;
}
