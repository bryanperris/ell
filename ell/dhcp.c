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
#include <linux/if_arp.h>
#include <net/ethernet.h>
#include <errno.h>

#include "private.h"
#include "random.h"
#include "net.h"
#include "dhcp.h"
#include "dhcp-private.h"

#define DHCP_MAGIC 0x63825363
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
#define DHCP_OPTION_CLIENT_IDENTIFIER 61 /* Section 9.14 */

/* RFC 2131, Table 1 */
enum dhcp_op_code {
	DHCP_OP_CODE_BOOTREQUEST = 1,
	DHCP_OP_CODE_BOOTREPLY = 2,
};

enum {
	DHCP_PORT_SERVER = 67,
	DHCP_PORT_CLIENT = 68,
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

const char *_dhcp_message_type_to_string(uint8_t type)
{
	switch(type) {
	case DHCP_MESSAGE_TYPE_DISCOVER:
		return "DHCPDISCOVER";
	case DHCP_MESSAGE_TYPE_OFFER:
		return "DHCPOFFER";
	case DHCP_MESSAGE_TYPE_REQUEST:
		return "DHCPREQUEST";
	case DHCP_MESSAGE_TYPE_DECLINE:
		return "DHCPDECLINE";
	case DHCP_MESSAGE_TYPE_ACK:
		return "DHCPACK";
	case DHCP_MESSAGE_TYPE_NAK:
		return "DHCPNAK";
	case DHCP_MESSAGE_TYPE_RELEASE:
		return "DHCPRELEASE";
	default:
		return "unknown";
	}
}

bool _dhcp_message_iter_init(struct dhcp_message_iter *iter,
				const struct dhcp_message *message, size_t len)
{
	if (!message)
		return false;

	if (len < sizeof(struct dhcp_message) + 4)
		return false;

	if (l_get_be32(message->options) != DHCP_MAGIC)
		return false;

	memset(iter, 0, sizeof(*iter));
	iter->message = message;
	iter->message_len = len;
	iter->pos = 4;
	iter->max = len - sizeof(struct dhcp_message);
	iter->options = message->options;
	iter->can_overload = true;

	return true;
}

static bool next_option(struct dhcp_message_iter *iter,
				uint8_t *t, uint8_t *l, const void **v)
{
	uint8_t type;
	uint8_t len;

	while (iter->pos < iter->max) {
		type = iter->options[iter->pos];

		switch (type) {
		case DHCP_OPTION_PAD:
			iter->pos += 1;
			continue;
		case DHCP_OPTION_END:
			return false;
		default:
			break;
		}

		if (iter->pos + 2 >= iter->max)
			return false;

		len = iter->options[iter->pos + 1];

		if (iter->pos + 2 + len > iter->max)
			return false;

		*t = type;
		*l = len;
		*v = &iter->options[iter->pos + 2];

		iter->pos += 2 + len;
		return true;
	}

	return false;
}

bool _dhcp_message_iter_next(struct dhcp_message_iter *iter, uint8_t *type,
				uint8_t *len, const void **data)
{
	bool r;
	uint8_t t, l;
	const void *v;

	do {
		r = next_option(iter, &t, &l, &v);
		if (!r) {
			iter->can_overload = false;

			if (iter->overload_file) {
				iter->options = iter->message->file;
				iter->pos = 0;
				iter->max = sizeof(iter->message->file);
				iter->overload_file = false;
				continue;
			}

			if (iter->overload_sname) {
				iter->options = iter->message->sname;
				iter->pos = 0;
				iter->max = sizeof(iter->message->sname);
				iter->overload_sname = false;
				continue;
			}

			return r;
		}

		switch (t) {
		case DHCP_OPTION_OVERLOAD:
			if (l != 1)
				continue;

			if (!iter->can_overload)
				continue;

			if (l_get_u8(v) & DHCP_OVERLOAD_FILE)
				iter->overload_file = true;

			if (l_get_u8(v) & DHCP_OVERLOAD_SNAME)
				iter->overload_sname = true;

			continue;
		default:
			if (type)
				*type = t;

			if (len)
				*len = l;

			if (data)
				*data = v;
			return r;
		}
	} while (true);

	return false;
}

int _dhcp_option_append(uint8_t **buf, size_t *buflen, uint8_t code,
					size_t optlen, const void *optval)
{
	if (!buf || !buflen)
		return -EINVAL;

	switch (code) {

	case DHCP_OPTION_PAD:
	case DHCP_OPTION_END:
		if (*buflen < 1)
			return -ENOBUFS;

		(*buf)[0] = code;
		*buf += 1;
		*buflen -= 1;
		break;

	default:
		if (*buflen < optlen + 2)
			return -ENOBUFS;

		if (!optval)
			return -EINVAL;

		(*buf)[0] = code;
		(*buf)[1] = optlen;
		memcpy(&(*buf)[2], optval, optlen);

		*buf += optlen + 2;
		*buflen -= (optlen + 2);

		break;
	}

	return 0;
}

static int dhcp_message_init(struct dhcp_message *message,
				enum dhcp_op_code op,
				uint8_t type, uint32_t xid,
				uint8_t **opt, size_t *optlen)
{
	int err;

	message->op = op;
	message->xid = L_CPU_TO_BE32(xid);

	if (*optlen < 4)
		return -ENOBUFS;

	*optlen -= 4;
	*opt = (uint8_t *)(message + 1);
	l_put_be32(DHCP_MAGIC, *opt);
	*opt += 4;

	err = _dhcp_option_append(opt, optlen,
					DHCP_OPTION_MESSAGE_TYPE, 1, &type);
	if (err < 0)
		return err;

	return 0;
}

static void dhcp_message_set_address_type(struct dhcp_message *message,
						uint8_t addr_type,
						uint8_t addr_len)
{
	message->htype = addr_type;

	switch (addr_type) {
	case ARPHRD_ETHER:
		message->hlen = addr_len;
		break;
	default:
		message->hlen = 0;
	}
}

static inline int dhcp_message_optimize(struct dhcp_message *message,
					const uint8_t *end)
{
	/*
	 * Don't bother sending a full sized dhcp_message as it is most likely
	 * mostly zeros.  Instead truncate it at DHCP_OPTION_END and align to
	 * the nearest 4 byte boundary.  Many implementations expect a packet
	 * of a certain size or it is filtered, so we cap the length in
	 * accordance to RFC 1542:
	 * "The IP Total Length and UDP Length must be large enough to contain
	 * the minimal BOOTP header of 300 octets"
	 */
	size_t len = align_len(end - (uint8_t *) message, 4);
	if (len < 300)
		len = 300;

	return len;
}

#define DHCP_MIN_OPTIONS_SIZE 312

struct l_dhcp_client {
	enum dhcp_state state;
	unsigned long request_options[256 / BITS_PER_LONG];
	uint32_t ifindex;
	char *ifname;
	uint8_t addr[6];
	uint8_t addr_len;
	uint8_t addr_type;
	uint32_t xid;
	struct dhcp_transport *transport;
	bool have_addr : 1;
};

static inline void dhcp_enable_option(struct l_dhcp_client *client,
								uint8_t option)
{
	client->request_options[option / BITS_PER_LONG] |=
						1UL << (option % BITS_PER_LONG);
}

static int client_message_init(struct l_dhcp_client *client,
					struct dhcp_message *message,
					uint8_t type,
					uint8_t **opt, size_t *optlen)
{
	int err;

	err = dhcp_message_init(message, DHCP_OP_CODE_BOOTREQUEST,
				type, client->xid, opt, optlen);
	if (err < 0)
		return err;

	dhcp_message_set_address_type(message, client->addr_type,
							client->addr_len);
	/*
	 * RFC2132 section 4.1.1:
	 * The client MUST include its hardware address in the ’chaddr’ field,
	 * if necessary for delivery of DHCP reply messages.  Non-Ethernet
	 * interfaces will leave 'chaddr' empty and use the client identifier
	 * instead
	 */
	if (client->addr_type == ARPHRD_ETHER)
		memcpy(message->chaddr, &client->addr, client->addr_len);

	return 0;
}

static int dhcp_client_send_discover(struct l_dhcp_client *client)
{
	uint8_t *opt;
	size_t optlen = DHCP_MIN_OPTIONS_SIZE;
	size_t len = sizeof(struct dhcp_message) + optlen;
	L_AUTO_FREE_VAR(struct dhcp_message *, discover);
	int err;
	struct sockaddr_in si;

	discover = (struct dhcp_message *) l_new(uint8_t, len);

	err = client_message_init(client, discover,
					DHCP_MESSAGE_TYPE_DISCOVER,
					&opt, &optlen);
	if (err < 0)
		return err;

	err = _dhcp_option_append(&opt, &optlen, DHCP_OPTION_END, 0, NULL);
	if (err < 0)
		return err;

	len = dhcp_message_optimize(discover, opt);

	memset(&si, 0, sizeof(si));
	si.sin_family = AF_INET;
	si.sin_port = L_CPU_TO_BE16(DHCP_PORT_SERVER);
	si.sin_addr.s_addr = 0xffffffff;

	return client->transport->send(client->transport, &si, discover, len);
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

	_dhcp_transport_free(client->transport);
	l_free(client->ifname);

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

LIB_EXPORT bool l_dhcp_client_set_address(struct l_dhcp_client *client,
						uint8_t type,
						const uint8_t *addr,
						size_t addr_len)
{
	if (unlikely(!client))
		return false;

	switch (type) {
	case ARPHRD_ETHER:
		if (addr_len != ETH_ALEN)
			return false;
		break;
	default:
		return false;
	}

	client->addr_len = addr_len;
	memcpy(client->addr, addr, addr_len);
	client->addr_type = type;

	client->have_addr = true;

	return true;
}

LIB_EXPORT bool l_dhcp_client_set_interface_name(struct l_dhcp_client *client,
							const char *ifname)
{
	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP_STATE_INIT))
		return false;

	l_free(client->ifname);
	client->ifname = l_strdup(ifname);

	return true;
}

LIB_EXPORT bool l_dhcp_client_start(struct l_dhcp_client *client)
{
	int err;

	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP_STATE_INIT))
		return false;

	if (!client->have_addr) {
		uint8_t mac[6];

		if (!l_net_get_mac_address(client->ifindex, mac))
			return false;

		l_dhcp_client_set_address(client, ARPHRD_ETHER, mac, 6);
	}

	if (!client->ifname) {
		client->ifname = l_net_get_name(client->ifindex);

		if (!client->ifname)
			return false;
	}

	if (!client->transport) {
		client->transport =
			_dhcp_default_transport_new();

		if (!client->transport)
			return false;
	}

	if (client->transport->open)
		if (client->transport->open(client->transport, client->ifindex,
					client->ifname, DHCP_PORT_CLIENT) < 0)
			return false;

	l_getrandom(&client->xid, sizeof(client->xid));

	err = dhcp_client_send_discover(client);
	return err >= 0;
}
