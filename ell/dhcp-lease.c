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

#include <linux/types.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "private.h"
#include "dhcp.h"
#include "dhcp-private.h"

struct l_dhcp_lease *_dhcp_lease_new(void)
{
	struct l_dhcp_lease *ret = l_new(struct l_dhcp_lease, 1);

	return ret;
}

void _dhcp_lease_free(struct l_dhcp_lease *lease)
{
	if (!lease)
		return;

	l_free(lease);
}

struct l_dhcp_lease *_dhcp_lease_parse_options(struct dhcp_message_iter *iter)
{
	struct l_dhcp_lease *lease = _dhcp_lease_new();
	uint8_t t, l;
	const void *v;

	while (_dhcp_message_iter_next(iter, &t, &l, &v)) {
		switch (t) {
		case L_DHCP_OPTION_IP_ADDRESS_LEASE_TIME:
			if (l == 4)
				lease->lifetime = l_get_be32(v);
			break;
		case L_DHCP_OPTION_SERVER_IDENTIFIER:
			if (l == 4)
				lease->server_address = l_get_u32(v);
			break;
		case L_DHCP_OPTION_SUBNET_MASK:
			if (l == 4)
				lease->subnet_mask = l_get_u32(v);
			break;
		case L_DHCP_OPTION_ROUTER:
			if (l == 4)
				lease->router = l_get_u32(v);
			break;
		case L_DHCP_OPTION_RENEWAL_T1_TIME:
			if (l == 4)
				lease->t1 = l_get_be32(v);
			break;
		case L_DHCP_OPTION_REBINDING_T2_TIME:
			if (l == 4)
				lease->t2 = l_get_be32(v);
			break;
		case L_DHCP_OPTION_BROADCAST_ADDRESS:
			if (l == 4)
				lease->broadcast = l_get_u32(v);
			break;
		default:
			break;
		}
	}

	if (!lease->server_address || !lease->lifetime)
		goto error;

	if (lease->lifetime < 10)
		goto error;

	if (!lease->t1)
		lease->t1 = lease->lifetime / 2;

	if (!lease->t2)
		lease->t2 = lease->lifetime * 7 / 8;

	if (lease->t1 > lease->t2)
		goto error;

	if (lease->t2 > lease->lifetime)
		goto error;

	return lease;
error:
	l_free(lease);
	return NULL;
}

static inline char *get_ip(uint32_t ip)
{
	struct in_addr addr;

	if (ip == 0)
		return NULL;

	addr.s_addr = ip;
	return l_strdup(inet_ntoa(addr));
}

LIB_EXPORT char *l_dhcp_lease_get_address(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return NULL;

	return get_ip(lease->address);
}

LIB_EXPORT char *l_dhcp_lease_get_gateway(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return NULL;

	return get_ip(lease->router);
}

LIB_EXPORT char *l_dhcp_lease_get_netmask(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return NULL;

	return get_ip(lease->subnet_mask);
}

LIB_EXPORT char *l_dhcp_lease_get_broadcast(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return NULL;

	return get_ip(lease->broadcast);
}

LIB_EXPORT char *l_dhcp_lease_get_server_id(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return NULL;

	return get_ip(lease->server_address);
}

LIB_EXPORT uint32_t l_dhcp_lease_get_t1(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return 0;

	return lease->t1;
}

LIB_EXPORT uint32_t l_dhcp_lease_get_t2(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return 0;

	return lease->t2;
}

LIB_EXPORT uint32_t l_dhcp_lease_get_lifetime(const struct l_dhcp_lease *lease)
{
	if (unlikely(!lease))
		return 0;

	return lease->lifetime;
}
