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

#include <netinet/ip.h>
#include <linux/types.h>
#include <errno.h>

#include "private.h"
#include "dhcp.h"
#include "dhcp-private.h"

#define BITS_PER_LONG (sizeof(unsigned long) * 8)

#define DHCP_OPTION_PAD 0 /* RFC 2132, Section 3.1 */
#define DHCP_OPTION_END 255 /* RFC 2132, Section 3.2 */

/* RFC 2132, Section 9.3. Option Overload */
#define DHCP_OPTION_OVERLOAD 52
enum dhcp_option_overload {
	DHCP_OVERLOAD_FILE = 1,
	DHCP_OVERLOAD_SNAME = 2,
	DHCP_OVERLOAD_BOTH = 3,
};

/* RFC 2132, Section 9.6. DHCP Message Type */
#define DHCP_OPTION_MESSAGE_TYPE 53
enum dhcp_message_type {
	DHCP_MESSAGE_TYPE_DISCOVER = 1,
	DHCP_MESSAGE_TYPE_OFFER = 2,
	DHCP_MESSAGE_TYPE_REQUEST = 3,
	DHCP_MESSAGE_TYPE_DECLINE = 4,
	DHCP_MESSAGE_TYPE_ACK = 5,
	DHCP_MESSAGE_TYPE_NAK = 6,
	DHCP_MESSAGE_TYPE_RELEASE = 7,
	DHCP_MESSAGE_TYPE_INFORM = 8,
};

#define DHCP_OPTION_PARAMETER_REQUEST_LIST 55 /* Section 9.8 */

/* RFC 2131, Table 1 */
enum dhcp_op_code {
	DHCP_OP_CODE_BOOTREQUEST = 1,
	DHCP_OP_CODE_BOOTREPLY = 2,
};

enum dhcp_state {
	DHCP_STATE_INIT,
	DHCP_STATE_SELECTING,
	DHCP_STATE_INIT_REBOOT,
	DHCP_STATE_REBOOTING,
	DHCP_STATE_REQUESTING,
	DHCP_STATE_BOUND,
	DHCP_STATE_RENEWING,
	DHCP_STATE_REBINDING,
};

struct l_dhcp_client {
	enum dhcp_state state;
	unsigned long request_options[256 / BITS_PER_LONG];
	uint32_t ifindex;
};

static inline void dhcp_enable_option(struct l_dhcp_client *client,
								uint8_t option)
{
	client->request_options[option / BITS_PER_LONG] |=
						1UL << (option % BITS_PER_LONG);
}

LIB_EXPORT struct l_dhcp_client *l_dhcp_client_new(uint32_t ifindex)
{
	struct l_dhcp_client *client;

	client = l_new(struct l_dhcp_client, 1);

	client->state = DHCP_STATE_INIT;
	client->ifindex = ifindex;

	/* Enable these options by default */
	dhcp_enable_option(client, L_DHCP_OPTION_SUBNET_MASK);
	dhcp_enable_option(client, L_DHCP_OPTION_ROUTER);
	dhcp_enable_option(client, L_DHCP_OPTION_HOST_NAME);
	dhcp_enable_option(client, L_DHCP_OPTION_DOMAIN_NAME);
	dhcp_enable_option(client, L_DHCP_OPTION_DOMAIN_NAME_SERVER);
	dhcp_enable_option(client, L_DHCP_OPTION_NTP_SERVERS);

	return client;
}

LIB_EXPORT void l_dhcp_client_destroy(struct l_dhcp_client *client)
{
	if (unlikely(!client))
		return;

	l_free(client);
}

LIB_EXPORT bool l_dhcp_client_add_request_option(struct l_dhcp_client *client,
								uint8_t option)
{
	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP_STATE_INIT))
		return false;

	switch (option) {
	case DHCP_OPTION_PAD:
	case DHCP_OPTION_END:
	case DHCP_OPTION_OVERLOAD:
	case DHCP_OPTION_MESSAGE_TYPE:
	case DHCP_OPTION_PARAMETER_REQUEST_LIST:
		return false;
	}

	dhcp_enable_option(client, option);

	return true;
}
