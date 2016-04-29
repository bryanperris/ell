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

static bool do_print = true;

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	l_info("%s%s", prefix, str);
}

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
	0x6c, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x57, 0x04, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x2f, 0x66, 0x6f, 0x6f, 0x2f, 0x62, 0x61, 0x72, 0x00, 0x00, 0x6f, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x46, 0x6f, 0x6f, 0x62, 0x61, 0x72, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x66, 0x6f, 0x6f, 0x2e, 0x62, 0x61, 0x72, 0x00, 0x00, 0x73, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x66, 0x6f, 0x6f, 0x2e, 0x62, 0x61, 0x72, 0x00, 0x00, 0x73, 0x13, 0x29,
	0x42, 0x5a, 0x00, 0x00, 0x01, 0xff, 0xe0, 0xff, 0x20, 0x00, 0x00, 0x00,
	0xe8, 0xff, 0xff, 0xff, 0x18, 0x00, 0x00, 0x00, 0x9d, 0xff, 0xff, 0xff,
	0x7d, 0x7f, 0x00, 0x00, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x40, 0x00, 0x28, 0x62, 0x79,
	0x6e, 0x71, 0x69, 0x75, 0x78, 0x74, 0x64, 0x29, 0x6e,
};

static const struct message_data message_data_basic_1 = {
	.type		= "method_call",
	.path		= "/foo/bar",
	.interface	= "foo.bar",
	.member		= "Foobar",
	.destination	= "foo.bar",
	.signature	= "bynqiuxtd",
	.binary		= basic_1,
	.binary_len	= sizeof(basic_1),
};

static const unsigned char message_binary_complex_1[] = {
	0x6c, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x57, 0x04, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x2f, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
	0x2f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x00, 0x00, 0x6f, 0x00, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6d, 0x65, 0x74, 0x68,
	0x6f, 0x64, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x6f, 0x6d, 0x2e,
	0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x69, 0x6e, 0x74, 0x65,
	0x72, 0x66, 0x61, 0x63, 0x65, 0x00, 0x00, 0x73, 0x06, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x63, 0x6f, 0x6d, 0x2e, 0x65, 0x78, 0x61, 0x6d,
	0x70, 0x6c, 0x65, 0x00, 0x00, 0x73, 0x1e, 0x31, 0x58, 0x6e, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x2f, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x78, 0x61,
	0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x4e, 0x61, 0x6d, 0x65, 0x00, 0x00, 0x00, 0x00,
	0x4c, 0x69, 0x6e, 0x75, 0x73, 0x20, 0x54, 0x6f, 0x72, 0x76, 0x61, 0x6c,
	0x64, 0x73, 0x00, 0x00, 0x73, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x44, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x65, 0x72, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x62, 0x0a, 0x1a, 0x34, 0x14, 0x00,
	0x28, 0x6f, 0x61, 0x7b, 0x73, 0x76, 0x7d, 0x29, 0x82,
};

static const struct message_data message_data_complex_1 = {
	.type		= "method_call",
	.path		= "/com/example/object",
	.interface	= "com.example.interface",
	.member		= "method",
	.destination	= "com.example",
	.signature	= "oa{sv}",
	.binary		= message_binary_complex_1,
	.binary_len	= sizeof(message_binary_complex_1),
};

static const unsigned char message_binary_empty_sig[] = {
	0x6c, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x57, 0x04, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x2f, 0x66, 0x6f, 0x6f, 0x2f, 0x62, 0x61, 0x72, 0x00, 0x00, 0x6f, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x46, 0x6f, 0x6f, 0x62, 0x61, 0x72, 0x00, 0x00, 0x73, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x66, 0x6f, 0x6f, 0x2e, 0x62, 0x61, 0x72, 0x00, 0x00, 0x73, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x66, 0x6f, 0x6f, 0x2e, 0x62, 0x61, 0x72, 0x00, 0x00, 0x73, 0x13, 0x29,
	0x42, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x28, 0x29, 0x6e,
};

static const struct message_data message_data_empty_sig = {
	.type		= "method_call",
	.path		= "/foo/bar",
	.interface	= "foo.bar",
	.member		= "Foobar",
	.destination	= "foo.bar",
	.signature	= "",
	.binary		= message_binary_empty_sig,
	.binary_len	= sizeof(message_binary_empty_sig),
};

static struct l_dbus_message *check_message(const struct message_data *msg_data)
{
	struct l_dbus_message *msg;

	msg = dbus_message_from_blob(msg_data->binary, msg_data->binary_len,
					NULL, 0);
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

static struct l_dbus_message *build_message(const struct message_data *msg_data)
{
	struct l_dbus_message *msg;

	msg = _dbus_message_new_method_call(2, msg_data->destination,
			msg_data->path, msg_data->interface, msg_data->member);
	assert(msg);

	return msg;
}

static void compare_message(struct l_dbus_message *msg,
					const struct message_data *msg_data)
{
	bool result;

	if (do_print) {
		void *blob;
		void *header, *body;
		size_t header_size, body_size;

		header = _dbus_message_get_header(msg, &header_size);
		body = _dbus_message_get_body(msg, &body_size);
		blob = l_malloc(header_size + body_size);
		memcpy(blob, header, header_size);
		memcpy(blob + header_size, body, body_size);

		l_util_hexdump(true, blob, header_size + body_size,
				do_debug, "[MSG] ");

		l_free(blob);

		l_util_hexdump(true, msg_data->binary, msg_data->binary_len,
							do_debug, "[MSG] ");
	}

	result = dbus_message_compare(msg, msg_data->binary,
						msg_data->binary_len);
	assert(result);

	l_dbus_message_unref(msg);
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
	assert(d == 5.0);

	l_dbus_message_unref(msg);
}

static void build_basic_1(const void *data)
{
	struct l_dbus_message *msg = build_message(data);
	bool result;

	result = l_dbus_message_set_arguments(msg, "bynqiuxtd", true, 255,
						-32, 32, -24, 24,
						(uint64_t) 140179142606749,
						(int64_t) 99, 5.0);
	assert(result);

	_dbus_message_set_serial(msg, 1111);

	compare_message(msg, data);
}

static void check_complex_1(const void *data)
{
	struct l_dbus_message *msg = check_message(data);
	struct l_dbus_message_iter dict, iter;
	const char *path, *str;
	bool result, val;

	result = l_dbus_message_get_arguments(msg, "oa{sv}", &path, &dict);
	assert(result);
	assert(!strcmp(path, "/com/example/object"));

	result = l_dbus_message_iter_next_entry(&dict, &str, &iter);
	assert(result);
	assert(!strcmp(str, "Name"));

	result = l_dbus_message_iter_get_variant(&iter, "s", &str);
	assert(result);
	assert(!strcmp(str, "Linus Torvalds"));

	result = l_dbus_message_iter_next_entry(&dict, &str, &iter);
	assert(result);
	assert(!strcmp(str, "Developer"));

	result = l_dbus_message_iter_get_variant(&iter, "b", &val);
	assert(result);
	assert(val);

	result = l_dbus_message_iter_next_entry(&dict, &str, &iter);
	assert(!result);

	l_dbus_message_unref(msg);
}

static void build_complex_1(const void *data)
{
	struct l_dbus_message *msg = build_message(data);
	bool result;

	result = l_dbus_message_set_arguments(msg, "oa{sv}",
						"/com/example/object", 2,
						"Name", "s", "Linus Torvalds",
						"Developer", "b", true);
	assert(result);

	_dbus_message_set_serial(msg, 1111);

	compare_message(msg, data);
}

static void check_empty_sig(const void *data)
{
	struct l_dbus_message *msg = check_message(data);

	assert(l_dbus_message_get_arguments(msg, ""));

	l_dbus_message_unref(msg);
}

static void build_empty_sig(const void *data)
{
	struct l_dbus_message *msg = build_message(data);
	bool result;

	result = l_dbus_message_set_arguments(msg, "");
	assert(result);

	_dbus_message_set_serial(msg, 1111);

	compare_message(msg, data);
}

static void builder_rewind(const void *data)
{
	struct l_dbus_message *msg = build_message(data);
	struct l_dbus_message_builder *builder;
	bool b = true;

	builder = l_dbus_message_builder_new(msg);
	assert(builder);

	assert(l_dbus_message_builder_append_basic(builder, 'o',
							"/com/example/object"));

	assert(l_dbus_message_builder_enter_array(builder, "{sv}"));

	assert(_dbus_message_builder_mark(builder));

	assert(l_dbus_message_builder_enter_dict(builder, "sv"));
	assert(l_dbus_message_builder_append_basic(builder, 's', "Name"));
	assert(l_dbus_message_builder_enter_variant(builder, "s"));
	assert(l_dbus_message_builder_append_basic(builder, 's',
							"Invalid"));
	assert(l_dbus_message_builder_leave_variant(builder));
	assert(l_dbus_message_builder_leave_dict(builder));

	assert(_dbus_message_builder_rewind(builder));

	assert(l_dbus_message_builder_enter_dict(builder, "sv"));
	assert(l_dbus_message_builder_append_basic(builder, 's', "Name"));
	assert(l_dbus_message_builder_enter_variant(builder, "s"));
	assert(l_dbus_message_builder_append_basic(builder, 's',
							"Linus Torvalds"));
	assert(l_dbus_message_builder_leave_variant(builder));
	assert(l_dbus_message_builder_leave_dict(builder));

	assert(l_dbus_message_builder_enter_dict(builder, "sv"));
	assert(l_dbus_message_builder_append_basic(builder, 's', "Developer"));
	assert(l_dbus_message_builder_enter_variant(builder, "b"));
	assert(l_dbus_message_builder_append_basic(builder, 'b', &b));
	assert(l_dbus_message_builder_leave_variant(builder));
	assert(l_dbus_message_builder_leave_dict(builder));

	assert(l_dbus_message_builder_leave_array(builder));

	assert(l_dbus_message_builder_finalize(builder));
	l_dbus_message_builder_destroy(builder);

	compare_message(msg, data);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("Basic 1 (parse)", parse_basic_1, &message_data_basic_1);
	l_test_add("Basic 1 (build)", build_basic_1, &message_data_basic_1);

	l_test_add("Complex 1 (parse)", check_complex_1,
						&message_data_complex_1);
	l_test_add("Complex 1 (build)", build_complex_1,
						&message_data_complex_1);

	l_test_add("Empty signature (parse)", check_empty_sig,
						&message_data_empty_sig);
	l_test_add("Empty signature (build)", build_empty_sig,
						&message_data_empty_sig);

	l_test_add("Message Builder Rewind Complex 1", builder_rewind,
						&message_data_complex_1);

	return l_test_run();
}
