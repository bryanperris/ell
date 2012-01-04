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

#include <ell/ell.h>
#include <ell/dbus.h>

#include "ell/private.h"

struct message_data {
	const char *type;
	const char *path;
	const char *interface;
	const char *member;
	const char *destination;
	const char *signature;
	uint32_t serial;
	uint32_t reply_serial;
	bool no_reply;
	bool auto_start;
	uint32_t unix_fds;
	const unsigned char *binary;
	size_t binary_len;
};

static const unsigned char message_binary_hello[] = {
			0x6c, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x6e, 0x00, 0x00, 0x00,
			0x01, 0x01, 0x6f, 0x00, 0x15, 0x00, 0x00, 0x00,
			0x2f, 0x6f, 0x72, 0x67, 0x2f, 0x66, 0x72, 0x65,
			0x65, 0x64, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70,
			0x2f, 0x44, 0x42, 0x75, 0x73, 0x00, 0x00, 0x00,
			0x06, 0x01, 0x73, 0x00, 0x14, 0x00, 0x00, 0x00,
			0x6f, 0x72, 0x67, 0x2e, 0x66, 0x72, 0x65, 0x65,
			0x64, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x2e,
			0x44, 0x42, 0x75, 0x73, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x01, 0x73, 0x00, 0x14, 0x00, 0x00, 0x00,
			0x6f, 0x72, 0x67, 0x2e, 0x66, 0x72, 0x65, 0x65,
			0x64, 0x65, 0x73, 0x6b, 0x74, 0x6f, 0x70, 0x2e,
			0x44, 0x42, 0x75, 0x73, 0x00, 0x00, 0x00, 0x00,
			0x03, 0x01, 0x73, 0x00, 0x05, 0x00, 0x00, 0x00,
			0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x00, 0x00,
};

static const struct message_data message_data_hello = {
	.type		= "method_call",
	.path		= "/org/freedesktop/DBus",
	.interface	= "org.freedesktop.DBus",
	.member		= "Hello",
	.destination	= "org.freedesktop.DBus",
	.signature	= "",
	.serial		= 1,
	.reply_serial	= 0,
	.no_reply	= false,
	.auto_start	= true,
	.unix_fds	= 0,
	.binary		= message_binary_hello,
	.binary_len	= 128,
};

static void check_message(const void *data)
{
	const struct message_data *msg_data = data;
	struct l_dbus_message *msg;
	const char *destination;

	msg = dbus_message_build(msg_data->binary, msg_data->binary_len);

	destination = l_dbus_message_get_destination(msg);
	assert(destination);
	assert(!strcmp(msg_data->destination, destination));

	l_info("destination=%s", destination);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("Message: Hello", check_message, &message_data_hello);

	return l_test_run();
}
