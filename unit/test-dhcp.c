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

#include <ell/ell.h>

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

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("request-option", test_request_option, NULL);

	return l_test_run();
}
