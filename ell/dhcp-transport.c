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

#define _GNU_SOURCE
#include <linux/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <linux/if_packet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>

#include "io.h"
#include "util.h"
#include "private.h"
#include "dhcp-private.h"

struct dhcp_default_transport {
	struct dhcp_transport super;
	struct l_io *io;
};

/*
 * For efficiency and simplicity of implementation, this function assumes that
 * only the last buffer can have an odd number of bytes
 */
uint16_t _dhcp_checksumv(const struct iovec *iov, size_t iov_cnt)
{
	uint32_t sum = 0;
	size_t i, j;
	size_t len = 0;

	for (j = 0; j < iov_cnt; j++) {
		const uint16_t *check = iov[j].iov_base;

		len += iov[j].iov_len;

		for (i = 0; i < iov[j].iov_len / 2; i++)
			sum += check[i];
	}

	if (len & 0x01) {
		const uint8_t *odd = iov[j].iov_base;
		sum += odd[len - 1];
	}

        while (sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);

        return ~sum;
}

uint16_t _dhcp_checksum(const void *buf, size_t len)
{
	struct iovec iov[1];

	iov[0].iov_base = (void *) buf;
	iov[0].iov_len = len;

	return _dhcp_checksumv(iov, 1);
}

static bool _dhcp_default_transport_read_handler(struct l_io *io,
							void *userdata)
{
	struct dhcp_default_transport *transport = userdata;
	int fd = l_io_get_fd(io);
	char buf[1024];
	ssize_t len;

	len = read(fd, buf, sizeof(buf));
	if (len < 0)
		return false;

	if (transport->super.rx_cb)
		transport->super.rx_cb(buf, len, transport->super.rx_data);

	return true;
}

static int kernel_socket_open(uint32_t ifindex,
					const char *ifname, uint32_t port)
{
	int s;
	int err;
	int one = 1;
	struct sockaddr_in saddr;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -errno;

	if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one)) < 0)
		goto error;

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
		goto error;

	if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE,
					ifname, strlen(ifname) + 1) < 0)
		goto error;

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(port);
	saddr.sin_addr.s_addr = INADDR_ANY;

	err = bind(s, (struct sockaddr *) &saddr, sizeof(struct sockaddr_in));
	if (err < 0)
		goto error;

	return s;

error:
	TEMP_FAILURE_RETRY(close(s));
	return -errno;
}

static int _dhcp_default_transport_open(struct dhcp_transport *s,
					uint32_t ifindex, const char *ifname,
					uint32_t port)
{
	struct dhcp_default_transport *transport =
		l_container_of(s, struct dhcp_default_transport, super);
	int fd;

	if (transport->io)
		return -EALREADY;

	fd = kernel_socket_open(ifindex, ifname, port);
	if (fd < 0)
		return fd;

	transport->io = l_io_new(fd);
	l_io_set_close_on_destroy(transport->io, true);
	l_io_set_read_handler(transport->io,
					_dhcp_default_transport_read_handler,
					transport, NULL);

	transport->super.ifindex = ifindex;

	return 0;
}

static void dhcp_set_ip_udp_headers(struct iphdr *ip, struct udphdr *udp,
					uint32_t saddr, uint16_t sport,
					uint32_t daddr, uint16_t dport,
					const void *data, size_t len)
{
	struct iovec iov[3];

	ip->version = IPVERSION;
	ip->ihl = sizeof(struct iphdr) / 4;
	ip->tot_len = L_CPU_TO_BE16(len + sizeof(*ip) + sizeof(*udp));

	ip->protocol = IPPROTO_UDP;
	ip->saddr = L_CPU_TO_BE32(saddr);
	ip->daddr = L_CPU_TO_BE32(daddr);

	udp->source = L_CPU_TO_BE16(sport);
	udp->dest = L_CPU_TO_BE16(dport);

	udp->len = L_CPU_TO_BE16(len + sizeof(*udp));

	ip->check = udp->len;

	iov[0].iov_base = &ip->ttl;
	iov[0].iov_len = sizeof(*ip) - 8;
	iov[1].iov_base = udp;
	iov[1].iov_len = sizeof(*udp);
	iov[2].iov_base = (void *) data;
	iov[2].iov_len = len;
	udp->check = _dhcp_checksumv(iov, 3);

	ip->ttl = IPDEFTTL;
	ip->check = 0;

	iov[0].iov_base = ip;
	iov[0].iov_len = sizeof(*ip);
	ip->check = _dhcp_checksumv(iov, 1);
}

static int _dhcp_default_transport_broadcast(struct dhcp_transport *s,
						uint32_t saddr, uint16_t sport,
						uint32_t daddr, uint16_t dport,
						const void *data, size_t len)
{
	int sk;
	struct sockaddr_ll addr;
	struct iovec iov[3];
	struct iphdr ip;
	struct udphdr udp;
	struct msghdr msg;

	sk = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_IP));
	if (sk < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_IP);
	addr.sll_ifindex = s->ifindex;
	addr.sll_halen = ETH_ALEN;
	memset(addr.sll_addr, 0xff, ETH_ALEN);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		goto error;

	dhcp_set_ip_udp_headers(&ip, &udp,
					saddr, sport, daddr, dport, data, len);
	iov[0].iov_base = &ip;
	iov[0].iov_len = sizeof(ip);
	iov[1].iov_base = &udp;
	iov[1].iov_len = sizeof(udp);
	iov[2].iov_base = (void *) data;
	iov[2].iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = 3;

	if (sendmsg(sk, &msg, 0) < 0)
		goto error;

	errno = 0;

error:
	close(sk);
	return -errno;
}

static int _dhcp_default_transport_send(struct dhcp_transport *s,
					const struct sockaddr_in *dest,
					const void *data, size_t len)
{
	struct dhcp_default_transport *transport =
		l_container_of(s, struct dhcp_default_transport, super);
	int fd = l_io_get_fd(transport->io);
	int err;

	err = sendto(fd, data, len, 0,
			(const struct sockaddr *) dest, sizeof(*dest));

	if (err < 0)
		return -errno;

	return 0;
}

static void _dhcp_default_transport_close(struct dhcp_transport *s)
{
	struct dhcp_default_transport *transport =
		l_container_of(s, struct dhcp_default_transport, super);

	l_io_destroy(transport->io);
	transport->io = NULL;
}

struct dhcp_transport *_dhcp_default_transport_new(void)
{
	struct dhcp_default_transport *transport;
	transport = l_new(struct dhcp_default_transport, 1);

	transport->super.open = _dhcp_default_transport_open;
	transport->super.close = _dhcp_default_transport_close;
	transport->super.send = _dhcp_default_transport_send;
	transport->super.broadcast = _dhcp_default_transport_broadcast;

	return &transport->super;
}

void _dhcp_transport_free(struct dhcp_transport *transport)
{
	if (!transport)
		return;

	if (transport->close)
		transport->close(transport);

	l_free(transport);
}

void _dhcp_transport_set_rx_callback(struct dhcp_transport *transport,
					dhcp_transport_rx_cb_t rx_cb,
					void *userdata)
{
	if (!transport)
		return;

	transport->rx_cb = rx_cb;
	transport->rx_data = userdata;
}
