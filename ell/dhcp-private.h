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

/* RFC 2131, Figure 1 */
struct dhcp_message {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	__be32 xid;
	__be16 secs;
	__be16 flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	uint8_t options[0];
} __attribute__ ((packed));

struct dhcp_message_iter {
	const struct dhcp_message *message;
	size_t message_len;
	const uint8_t *options;
	uint16_t pos;
	uint16_t max;
	bool can_overload : 1;
	bool overload_sname : 1;
	bool overload_file : 1;
};

const char *_dhcp_message_type_to_string(uint8_t type);

uint16_t _dhcp_checksum(const void *buf, size_t len);
uint16_t _dhcp_checksumv(const struct iovec *iov, size_t iov_cnt);

struct dhcp_transport {
	int (*open)(struct dhcp_transport *s, uint32_t ifindex,
					const char *ifname, uint32_t port);
	int (*send)(struct dhcp_transport *transport,
					const struct sockaddr_in *dest,
					const void *data, size_t len);
	int (*broadcast)(struct dhcp_transport *transport,
						uint32_t saddr, uint16_t sport,
						uint32_t daddr, uint16_t dport,
						const void *data, size_t len);
	void (*close)(struct dhcp_transport *transport);
	uint32_t ifindex;
};

struct dhcp_transport *_dhcp_default_transport_new(void);
void _dhcp_transport_free(struct dhcp_transport *transport);

bool _dhcp_message_iter_init(struct dhcp_message_iter *iter,
				const struct dhcp_message *message, size_t len);
bool _dhcp_message_iter_next(struct dhcp_message_iter *iter, uint8_t *type,
				uint8_t *len, const void **data);

int _dhcp_option_append(uint8_t **buf, size_t *buflen, uint8_t code,
					size_t optlen, const void *optval);
