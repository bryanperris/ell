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
#include <ell/dbus.h>
#include "ell/dbus-private.h"

static bool do_print = true;

struct message_data {
	const char *type;
	const char *path;
	const char *interface;
	const char *member;
	const char *destination;
	const char *signature;
	const unsigned char *binary;
	size_t binary_len;
};

static const unsigned char basic_1[] = {
	0x6c, 0x01, 0x00, 0x02, 0x28, 0x00, 0x00, 0x00, 0x57, 0x04, 0x00, 0x00,
	0x79, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x2f, 0x66, 0x6f, 0x6f, 0x2f, 0x62, 0x61, 0x72, 0x00, 0x00, 0x6f, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x46, 0x6f, 0x6f, 0x62, 0x61, 0x72, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x66, 0x6f, 0x6f, 0x2e, 0x62, 0x61, 0x72, 0x00, 0x00, 0x73, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x66, 0x6f, 0x6f, 0x2e, 0x62, 0x61, 0x72, 0x00, 0x00, 0x73, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x62, 0x79, 0x6e, 0x71, 0x69, 0x75, 0x78, 0x74, 0x64, 0x00, 0x00, 0x67,
	0x13, 0x29, 0x42, 0x5a, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0xff, 0xe0, 0xff, 0x20, 0x00, 0x00, 0x00, 0xe8, 0xff, 0xff, 0xff,
	0x18, 0x00, 0x00, 0x00, 0x9d, 0xff, 0xff, 0xff, 0x7d, 0x7f, 0x00, 0x00,
	0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd3, 0xe4, 0x42, 0x00,
	0x00, 0x00, 0x00, 0x00,
};

static const struct message_data message_data_basic_1 = {
	.type		= "method_call",
	.path		= "/foo/bar",
	.interface	= "foo.bar",
	.member		= "Foobar",
	.destination	= "foo.bar",
	.signature	= "bynqiuxtd",
	.binary		= basic_1,
	.binary_len	= 184,
};

static struct l_dbus_message *check_message(const struct message_data *msg_data)
{
	struct l_dbus_message *msg;

	msg = dbus_message_from_blob(msg_data->binary, msg_data->binary_len);
	assert(msg);

	if (msg_data->path) {
		const char *path = l_dbus_message_get_path(msg);
		assert(path);
		assert(!strcmp(msg_data->path, path));

		if (do_print)
			l_info("path=%s", path);
	}

	if (msg_data->interface) {
		const char *interface = l_dbus_message_get_interface(msg);
		assert(interface);
		assert(!strcmp(msg_data->interface, interface));

		if (do_print)
			l_info("interface=%s", interface);
	}

	if (msg_data->member) {
		const char *member = l_dbus_message_get_member(msg);
		assert(member);
		assert(!strcmp(msg_data->member, member));

		if (do_print)
			l_info("member=%s", member);
	}
	if (msg_data->destination) {
		const char *destination = l_dbus_message_get_destination(msg);
		assert(destination);
		assert(!strcmp(msg_data->destination, destination));

		if (do_print)
			l_info("destination=%s", destination);
	}

	if (msg_data->signature) {
		const char *signature = l_dbus_message_get_signature(msg);
		assert(signature);
		assert(!strcmp(msg_data->signature, signature));

		if (do_print)
			l_info("signature=%s", signature);
	}

	return msg;
}

static void parse_basic_1(const void *data)
{
	struct l_dbus_message *msg = check_message(data);
	bool result;
	bool b;
	uint8_t y;
	uint16_t q;
	int16_t n;
	uint32_t u;
	int32_t i;
	uint64_t t;
	int64_t x;
	double d;

	result = l_dbus_message_get_arguments(msg, "bynqiuxtd", &b, &y, &n, &q,
						&i, &u, &x, &t, &d);
	assert(result);

	assert(b == true);
	assert(y == 255);
	assert(n == -32);
	assert(q == 32);
	assert(i == -24);
	assert(u == 24);
	assert(x == 140179142606749);
	assert(t == 99);
	assert(d > 0);

	l_dbus_message_unref(msg);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("Basic 1 (parse)", parse_basic_1, &message_data_basic_1);

	return l_test_run();
}
