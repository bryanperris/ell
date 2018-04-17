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

#ifndef __ELL_DHCP_H
#define __ELL_DHCP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

struct l_dhcp_client;

/* RFC 2132 */
enum l_dhcp_option {
	L_DHCP_OPTION_SUBNET_MASK = 1, /* Section 3.3  */
	L_DHCP_OPTION_ROUTER = 3, /* Section 3.5 */
	L_DHCP_OPTION_DOMAIN_NAME_SERVER = 6, /* Section 3.8 */
	L_DHCP_OPTION_HOST_NAME = 12, /* Section 3.14 */
	L_DHCP_OPTION_DOMAIN_NAME = 15, /* Section 3.17 */
	L_DHCP_OPTION_NTP_SERVERS = 42, /* Section 8.3 */
	L_DHCP_OPTION_REQUESTED_IP_ADDRESS = 50, /* Section 9.1 */
	L_DHCP_OPTION_IP_ADDRESS_LEASE_TIME = 51, /* Section 9.2 */
	L_DHCP_OPTION_SERVER_IDENTIFIER = 54, /* Section 9.7 */
};

struct l_dhcp_client *l_dhcp_client_new(uint32_t ifindex);
bool l_dhcp_client_add_request_option(struct l_dhcp_client *client,
								uint8_t option);
void l_dhcp_client_destroy(struct l_dhcp_client *client);

bool l_dhcp_client_set_address(struct l_dhcp_client *client, uint8_t type,
					const uint8_t *addr, size_t addr_len);
bool l_dhcp_client_set_interface_name(struct l_dhcp_client *client,
							const char *ifname);

bool l_dhcp_client_start(struct l_dhcp_client *client);
bool l_dhcp_client_stop(struct l_dhcp_client *client);
#ifdef __cplusplus
}
#endif

#endif /* __ELL_DHCP_H */
