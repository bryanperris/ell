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

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("request-option", test_request_option, NULL);
	l_test_add("invalid-message-length", test_invalid_message_length, NULL);
	l_test_add("cookie", test_cookie, NULL);

	return l_test_run();
}
