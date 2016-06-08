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
#include "ell/dbus-private.h"

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

static void signal_message(struct l_dbus_message *message, void *user_data)
{
	const char *path, *interface, *member, *destination, *sender;

	path = l_dbus_message_get_path(message);
	destination = l_dbus_message_get_destination(message);

	l_info("path=%s destination=%s", path, destination);

	interface = l_dbus_message_get_interface(message);
	member = l_dbus_message_get_member(message);

	l_info("interface=%s member=%s", interface, member);

	sender = l_dbus_message_get_sender(message);

	l_info("sender=%s", sender);
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

static void client_ready_callback(void *user_data)
{
	struct l_dbus *dbus = user_data;

	l_info("client ready");

	l_dbus_method_call(dbus, "org.test",
				"/test",
				"org.test", "TestMethod",
				NULL,
				NULL, NULL, NULL);
}

static void service_name_acquire_callback(struct l_dbus *dbus, bool success,
						bool queued, void *user_data)
{
	if (!success)
		l_info("Failed to acquire name");
}

static void service_ready_callback(void *user_data)
{
	struct l_dbus *dbus = user_data;
	struct l_dbus_message *message;

	l_dbus_name_acquire(dbus, "org.test", false, false, false,
				service_name_acquire_callback, NULL);

	l_info("service ready");

	message = l_dbus_message_new_signal(dbus, "/test",
					"org.test", "TestSignal");
	l_dbus_message_set_arguments(message, "");
	l_dbus_send(dbus, message);
}

static void setup_test_interface(struct l_dbus_interface *interface)
{
	l_dbus_interface_method(interface, "TestMethod", 0,
				test_method_call, "", "");
}

int main(int argc, char *argv[])
{
	struct l_dbus *service;
	struct l_dbus *client;
	char bus_name[16];
	char bus_address[64];
	int bus_fd;
	struct l_signal *signal;
	sigset_t mask;

	if (!l_main_init())
		return -1;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	signal = l_signal_create(&mask, signal_handler, NULL, NULL);

	l_log_set_stderr();

	snprintf(bus_name, sizeof(bus_name), "%u-ell-test", getuid());

	bus_fd = _dbus_kernel_create_bus(bus_name);
	if (bus_fd < 0) {
		l_warn("kdbus not available");
		return EXIT_SUCCESS;
	}

	snprintf(bus_address, sizeof(bus_address),
				"kernel:path=/dev/kdbus/%s/bus", bus_name);

	service = l_dbus_new(bus_address);
	assert(service);

	l_dbus_set_debug(service, do_debug, "[SERVICE] ", NULL);
	l_dbus_set_ready_handler(service, service_ready_callback,
					service, NULL);

	if (!l_dbus_register_interface(service, "org.test",
					setup_test_interface, NULL, false)) {
		l_info("Unable to register interface");
		goto error;
	}

	if (!l_dbus_object_add_interface(service, "/test", "org.test", NULL)) {
		l_info("Unable to instantiate interface");
		goto error;
	}

	client = l_dbus_new(bus_address);
	assert(client);

	l_dbus_set_debug(client, do_debug, "[CLIENT] ", NULL);
	l_dbus_set_ready_handler(client, client_ready_callback, client, NULL);
	l_dbus_add_signal_watch(client, "org.test", NULL, NULL, NULL,
				L_DBUS_MATCH_NONE, signal_message, NULL);

	l_main_run();

	l_dbus_destroy(client);
error:
	l_dbus_destroy(service);

	close(bus_fd);

	l_signal_remove(signal);

	l_main_exit();

	return EXIT_SUCCESS;
}
