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

struct l_dhcp_client;

enum {
	DHCP_PORT_SERVER = 67,
	DHCP_PORT_CLIENT = 68,
};

/* RFC 2131, Table 1 */
enum dhcp_op_code {
	DHCP_OP_CODE_BOOTREQUEST = 1,
	DHCP_OP_CODE_BOOTREPLY = 2,
};

#define DHCP_MAGIC 0x63825363

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
	__be32 magic;
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
const char *_dhcp_option_to_string(uint8_t option);

uint16_t _dhcp_checksum(const void *buf, size_t len);
uint16_t _dhcp_checksumv(const struct iovec *iov, size_t iov_cnt);

typedef void (*dhcp_transport_rx_cb_t)(const void *, size_t, void *);

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
	dhcp_transport_rx_cb_t rx_cb;
	void *rx_data;
};

struct dhcp_transport *_dhcp_default_transport_new(void);
void _dhcp_transport_free(struct dhcp_transport *transport);
void _dhcp_transport_set_rx_callback(struct dhcp_transport *transport,
					dhcp_transport_rx_cb_t rx_cb,
					void *userdata);

bool _dhcp_message_iter_init(struct dhcp_message_iter *iter,
				const struct dhcp_message *message, size_t len);
bool _dhcp_message_iter_next(struct dhcp_message_iter *iter, uint8_t *type,
				uint8_t *len, const void **data);

int _dhcp_option_append(uint8_t **buf, size_t *buflen, uint8_t code,
					size_t optlen, const void *optval);

bool _dhcp_client_set_transport(struct l_dhcp_client *client,
					struct dhcp_transport *transport);
void _dhcp_client_override_xid(struct l_dhcp_client *client, uint32_t xid);

struct l_dhcp_lease {
	uint32_t address;
	uint32_t server_address;
	uint32_t subnet_mask;
	uint32_t broadcast;
	uint32_t lifetime;
	uint32_t t1;
	uint32_t t2;
	uint32_t router;
	uint32_t *dns;
};

struct l_dhcp_lease *_dhcp_lease_new(void);
void _dhcp_lease_free(struct l_dhcp_lease *lease);
struct l_dhcp_lease *_dhcp_lease_parse_options(struct dhcp_message_iter *iter);
