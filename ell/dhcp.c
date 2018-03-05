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
#include "dhcp-private.h"

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
