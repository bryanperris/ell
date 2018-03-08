/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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
#include <linux/types.h>
#include <errno.h>

#include <ell/ell.h>
#include "ell/dhcp-private.h"

static void test_request_option(const void *data)
{
	struct l_dhcp_client *dhcp;

	dhcp = l_dhcp_client_new(0);
	assert(dhcp);

	assert(!l_dhcp_client_add_request_option(NULL, 0));

	assert(l_dhcp_client_add_request_option(dhcp,
						L_DHCP_OPTION_SUBNET_MASK));
	assert(l_dhcp_client_add_request_option(dhcp,
						L_DHCP_OPTION_ROUTER));
	assert(l_dhcp_client_add_request_option(dhcp,
						L_DHCP_OPTION_HOST_NAME));
	assert(l_dhcp_client_add_request_option(dhcp,
						L_DHCP_OPTION_DOMAIN_NAME));
	assert(l_dhcp_client_add_request_option(dhcp,
					L_DHCP_OPTION_DOMAIN_NAME_SERVER));
	assert(l_dhcp_client_add_request_option(dhcp,
					L_DHCP_OPTION_NTP_SERVERS));
	assert(!l_dhcp_client_add_request_option(dhcp, 0));
	assert(!l_dhcp_client_add_request_option(dhcp, 255));
	assert(!l_dhcp_client_add_request_option(dhcp, 52));
	assert(!l_dhcp_client_add_request_option(dhcp, 53));
	assert(!l_dhcp_client_add_request_option(dhcp, 55));

	assert(l_dhcp_client_add_request_option(dhcp, 33));
	assert(l_dhcp_client_add_request_option(dhcp, 44));

	l_dhcp_client_destroy(dhcp);
}

static void test_invalid_message_length(const void *data)
{
	struct dhcp_message message;
	struct dhcp_message_iter iter;

	assert(!_dhcp_message_iter_init(&iter, NULL, 0));
	assert(!_dhcp_message_iter_init(&iter, &message, sizeof(message)));
}

static void test_cookie(const void *data)
{
	struct dhcp_message *message;
	size_t len = sizeof(struct dhcp_message) + 4;
	uint8_t *opt;
	struct dhcp_message_iter iter;

	message = (struct dhcp_message *) l_new(uint8_t, len);
	opt = (uint8_t *)(message + 1);
	opt[0] = 0xff;

	assert(!_dhcp_message_iter_init(&iter, message, len));

	opt[0] = 99;
	opt[1] = 130;
	opt[2] = 83;
	opt[3] = 99;

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(!_dhcp_message_iter_next(&iter, NULL, NULL, NULL));

	l_free(message);
}

struct option_test {
	uint8_t sname[64];
	int snamelen;
	uint8_t file[128];
	int filelen;
	uint8_t options[128];
	int len;
};

static const struct option_test option_test_1 = {
	.options = { 42, 5, 65, 66, 67, 68, 69 },
	.len = 7,
};

static const struct option_test option_test_2 = {
	.options = { 42, 5, 65, 66, 67, 68, 69, 0, 0, 53, 1, 5 },
	.len = 12,
};

static const struct option_test option_test_3 = {
	.options = { 8, 255, 70, 71, 72 },
	.len = 5,
};

static const struct option_test option_test_4 = {
	.options = { 0x35, 0x01, 0x05, 0x36, 0x04, 0x01, 0x00, 0xa8,
			0xc0, 0x33, 0x04, 0x00, 0x01, 0x51, 0x80, 0x01,
			0x04, 0xff, 0xff, 0xff, 0x00, 0x03, 0x04, 0xc0,
			0xa8, 0x00, 0x01, 0x06, 0x04, 0xc0, 0xa8, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, },
	.len = 40,
};

static const struct option_test option_test_5 = {
	.options = { 53, 1, 2, 42, 3, 0, 0, 0 },
	.len =  8,
};

static const struct option_test option_test_6 = {
	.options = { 42, 2, 1, 2, 44 },
	.len = 5,
};

static const struct option_test option_test_7 = {
	.file = { 222, 3, 1, 2, 3, 53, 1, 6 },
	.filelen = 8,
	.options = { 52, 0x1, 0x1 },
	.len = 3,
};

static const struct option_test option_test_8 = {
	.sname = { 1, 4, 1, 2, 3, 4, 53, 1, 5 },
	.snamelen = 9,
	.file = { 222, 3, 1, 2, 3 },
	.filelen = 5,
	.options = { 52, 0x1, 0x3 },
	.len = 3,
};

static struct dhcp_message *create_message(const struct option_test *test,
						size_t *out_len)
{
	struct dhcp_message *message;
	size_t len = sizeof(struct dhcp_message) + 4 + test->len;
	uint8_t *opt;

	message = (struct dhcp_message *) l_new(uint8_t, len);
	opt = (uint8_t *)(message + 1);

	opt[0] = 99;
	opt[1] = 130;
	opt[2] = 83;
	opt[3] = 99;

	if (test->options && test->len)
		memcpy(&opt[4], test->options, test->len);

	if (test->file && test->filelen <= 128)
		memcpy(&message->file, test->file, test->filelen);

	if (test->sname && test->snamelen <= 64)
		memcpy(&message->sname, test->sname, test->snamelen);

	if (out_len)
		*out_len = len;

	return message;
}

static void test_option_1(const void *data)
{
	const struct option_test *test = data;
	struct dhcp_message *message;
	struct dhcp_message_iter iter;
	size_t len;
	uint8_t t,l;

	message = create_message(test, &len);

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 42);
	assert(l == 5);
	assert(!_dhcp_message_iter_next(&iter, &t, &l, NULL));
	l_free(message);
}

static void test_option_2(const void *data)
{
	const struct option_test *test = data;
	struct dhcp_message *message;
	struct dhcp_message_iter iter;
	size_t len;
	uint8_t t,l;

	message = create_message(test, &len);

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 42);
	assert(l == 5);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 53);
	assert(l == 1);
	assert(!_dhcp_message_iter_next(&iter, &t, &l, NULL));
	l_free(message);
}

static void test_option_3(const void *data)
{
	const struct option_test *test = data;
	struct dhcp_message *message;
	struct dhcp_message_iter iter;
	size_t len;

	message = create_message(test, &len);

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(!_dhcp_message_iter_next(&iter, NULL, NULL, NULL));
	l_free(message);
}

static void test_option_4(const void *data)
{
	const struct option_test *test = data;
	struct dhcp_message *message;
	struct dhcp_message_iter iter;
	size_t len;
	uint8_t t,l;

	message = create_message(test, &len);

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 0x35);
	assert(l == 1);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 0x36);
	assert(l == 4);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 0x33);
	assert(l == 4);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 0x1);
	assert(l == 4);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 0x3);
	assert(l == 4);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 0x6);
	assert(l == 4);
	assert(!_dhcp_message_iter_next(&iter, &t, &l, NULL));
	l_free(message);
}

static void test_option_5(const void *data)
{
	const struct option_test *test = data;
	struct dhcp_message *message;
	struct dhcp_message_iter iter;
	size_t len;
	uint8_t t,l;

	message = create_message(test, &len);

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 53);
	assert(l == 1);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 42);
	assert(l == 3);
	assert(!_dhcp_message_iter_next(&iter, &t, &l, NULL));
	l_free(message);
}

static void test_option_6(const void *data)
{
	const struct option_test *test = data;
	struct dhcp_message *message;
	struct dhcp_message_iter iter;
	size_t len;
	uint8_t t,l;

	message = create_message(test, &len);

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 42);
	assert(l == 2);
	assert(!_dhcp_message_iter_next(&iter, NULL, NULL, NULL));
	l_free(message);
}

static void test_option_7(const void *data)
{
	const struct option_test *test = data;
	struct dhcp_message *message;
	struct dhcp_message_iter iter;
	size_t len;
	uint8_t t,l;

	message = create_message(test, &len);

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 222);
	assert(l == 3);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 53);
	assert(l == 1);
	assert(!_dhcp_message_iter_next(&iter, NULL, NULL, NULL));
	l_free(message);
}

static void test_option_8(const void *data)
{
	const struct option_test *test = data;
	struct dhcp_message *message;
	struct dhcp_message_iter iter;
	size_t len;
	uint8_t t, l;

	message = create_message(test, &len);

	assert(_dhcp_message_iter_init(&iter, message, len));
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 222);
	assert(l == 3);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 1);
	assert(l == 4);
	assert(_dhcp_message_iter_next(&iter, &t, &l, NULL));
	assert(t == 53);
	assert(l == 1);
	assert(!_dhcp_message_iter_next(&iter, NULL, NULL, NULL));
	l_free(message);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("request-option", test_request_option, NULL);
	l_test_add("invalid-message-length", test_invalid_message_length, NULL);
	l_test_add("cookie", test_cookie, NULL);

	l_test_add("option test 1", test_option_1, &option_test_1);
	l_test_add("option test 2", test_option_2, &option_test_2);
	l_test_add("option test 3", test_option_3, &option_test_3);
	l_test_add("option test 4", test_option_4, &option_test_4);
	l_test_add("option test 5", test_option_5, &option_test_5);
	l_test_add("option test 6", test_option_6, &option_test_6);
	l_test_add("option test 7", test_option_7, &option_test_7);
	l_test_add("option test 8", test_option_8, &option_test_8);

	return l_test_run();
}
