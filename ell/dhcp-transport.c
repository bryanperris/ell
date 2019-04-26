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
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <net/if_arp.h>

#include "io.h"
#include "util.h"
#include "private.h"
#include "dhcp-private.h"

struct dhcp_default_transport {
	struct dhcp_transport super;
	struct l_io *io;
	int udp_fd;
	char ifname[IFNAMSIZ];
	uint16_t port;
};

struct dhcp_packet {
	struct iphdr ip;
	struct udphdr udp;
	struct dhcp_message dhcp;
} __attribute__ ((packed));

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
	char buf[2048];
	ssize_t len;
	struct dhcp_packet *p;
	uint16_t c;

	len = read(fd, buf, sizeof(buf));
	if (len < 0)
		return false;

	p = (struct dhcp_packet *) buf;

	if (len < L_BE16_TO_CPU(p->ip.tot_len))
		return true;

	if (len < (ssize_t) (L_BE16_TO_CPU(p->udp.len) + sizeof(struct iphdr)))
		return true;

	c = p->ip.check;
	p->ip.check = 0;

	if (c != _dhcp_checksum(&p->ip, sizeof(struct iphdr)))
		return true;

	/* only compute if the UDP checksum is present, e.g. non-zero */
	if (p->udp.check) {
		c = p->udp.check;
		p->ip.check = p->udp.len;
		p->ip.ttl = 0;
		p->udp.check = 0;

		/*
		 * We fake the UDP pseudo-header by reusing bits of
		 * the IP header
		 */
		if (c != _dhcp_checksum(&p->ip.ttl,
					L_BE16_TO_CPU(p->udp.len) + 12))
			return true;
	}

	len -= sizeof(struct udphdr) - sizeof(struct iphdr);

	if (transport->super.rx_cb)
		transport->super.rx_cb(&p->dhcp, len, transport->super.rx_data);

	return true;
}

static void dhcp_set_ip_udp_headers(struct iphdr *ip, struct udphdr *udp,
					uint32_t saddr, uint16_t sport,
					uint32_t daddr, uint16_t dport,
					const void *data, size_t len)
{
	struct iovec iov[3];

	memset(ip, 0, sizeof(*ip));
	memset(udp, 0, sizeof(*udp));

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
	struct dhcp_default_transport *transport =
		l_container_of(s, struct dhcp_default_transport, super);
	struct sockaddr_ll addr;
	struct iovec iov[3];
	struct iphdr ip;
	struct udphdr udp;
	struct msghdr msg;

	dhcp_set_ip_udp_headers(&ip, &udp,
					saddr, sport, daddr, dport, data, len);
	iov[0].iov_base = &ip;
	iov[0].iov_len = sizeof(ip);
	iov[1].iov_base = &udp;
	iov[1].iov_len = sizeof(udp);
	iov[2].iov_base = (void *) data;
	iov[2].iov_len = len;

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_IP);
	addr.sll_ifindex = s->ifindex;
	addr.sll_halen = ETH_ALEN;
	memset(addr.sll_addr, 0xff, ETH_ALEN);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = 3;

	if (sendmsg(l_io_get_fd(transport->io), &msg, 0) < 0)
		goto error;

	errno = 0;

error:
	return -errno;
}

static int _dhcp_default_transport_send(struct dhcp_transport *s,
					const struct sockaddr_in *dest,
					const void *data, size_t len)
{
	struct dhcp_default_transport *transport =
		l_container_of(s, struct dhcp_default_transport, super);
	int err;

	err = sendto(transport->udp_fd, data, len, 0,
			(const struct sockaddr *) dest, sizeof(*dest));

	if (err < 0)
		return -errno;

	return 0;
}

static int kernel_udp_socket_open(const char *ifname,
					uint32_t addr, uint16_t port)
{
	int s;
	int err;
	int one = 1;
	struct sockaddr_in saddr;
	struct sock_filter filter[] = {
		/* ignore */
		BPF_STMT(BPF_RET + BPF_K, 0),
	};
	struct sock_fprog fprog = {
		.len = L_ARRAY_SIZE(filter),
		.filter = filter
	};

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -errno;

	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER,
						&fprog, sizeof(fprog)) < 0)
		goto error;

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
		goto error;

	if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE,
					ifname, strlen(ifname) + 1) < 0)
		goto error;

	/*
	 * Just in case we need to bind the address prior to it being
	 * configured via rtnl
	 */
	if (setsockopt(s, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one)) < 0)
		goto error;

	memset(&saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = L_CPU_TO_BE16(port);
	saddr.sin_addr.s_addr = addr;

	err = bind(s, (struct sockaddr *) &saddr, sizeof(struct sockaddr_in));
	if (err < 0)
		goto error;

	return s;

error:
	TEMP_FAILURE_RETRY(close(s));
	return -errno;
}

static int _dhcp_default_transport_bind(struct dhcp_transport *s,
							uint32_t saddr)
{
	struct dhcp_default_transport *transport =
		l_container_of(s, struct dhcp_default_transport, super);
	int fd;

	if (!transport->io)
		return -EIO;

	fd = kernel_udp_socket_open(transport->ifname, saddr, transport->port);
	if (fd < 0)
		return fd;

	transport->udp_fd = fd;

	return 0;
}

static int kernel_raw_socket_open(uint32_t ifindex, uint16_t port, uint32_t xid)
{
	int s;
	struct sockaddr_ll addr;
	struct sock_filter filter[] = {
		/* A <- packet length */
		BPF_STMT(BPF_LD + BPF_W + BPF_LEN, 0),
		/* A >= sizeof(dhcp_packet) ? */
		BPF_JUMP(BPF_JMP + BPF_JGE + BPF_K,
					sizeof(struct dhcp_packet), 1, 0),
		/* ignore */
		BPF_STMT(BPF_RET + BPF_K, 0),
		/* A <- IP version + Header length */
		BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 0),
		/* A <- A & 0xf0 (Mask off version */
		BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0xf0),
		/* A == IPVERSION (shifted left 4) ? */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPVERSION << 4, 1, 0),
		/* ignore */
		BPF_STMT(BPF_RET + BPF_K, 0),
		/* A <- IP version + Header length */
		BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 0),
		/* A <- A & 0x0f (Mask off IP Header Length */
		BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0x0f),
		/* A == 5 ? */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 5, 1, 0),
		/* ignore */
		BPF_STMT(BPF_RET + BPF_K, 0),
		/* A <- IP protocol */
		BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
				offsetof(struct dhcp_packet, ip.protocol)),
		/* IP protocol == UDP ? */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 1, 0),
		/* ignore */
		BPF_STMT(BPF_RET + BPF_K, 0),
		/* A <- Flags + Fragment offset */
		BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
				offsetof(struct dhcp_packet, ip.frag_off)),
		/* A <- A & 0x3fff (fragment flag + fragment offset) */
		BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0x3fff),
		/* A == 0 ? */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 1, 0),
		/* ignore */
		BPF_STMT(BPF_RET + BPF_K, 0),
		/* A <- UDP destination port */
		BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
				offsetof(struct dhcp_packet, udp.dest)),
		/* UDP destination port == DHCP client port ? */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, port, 1, 0),
		/* ignore */
		BPF_STMT(BPF_RET + BPF_K, 0),
		/* A <- DHCP op */
		BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
				offsetof(struct dhcp_packet, dhcp.op)),
		/* op == BOOTREPLY ? */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
				DHCP_OP_CODE_BOOTREPLY, 1, 0),
		/* ignore */
		BPF_STMT(BPF_RET + BPF_K, 0),
		/* A <- DHCP header type */
		BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
				offsetof(struct dhcp_packet, dhcp.htype)),
		/* header type == arp_type ? */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPHRD_ETHER, 1, 0),
		/* ignore */
		BPF_STMT(BPF_RET + BPF_K, 0),
		/* A <- client identifier */
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
				offsetof(struct dhcp_packet, dhcp.xid)),
		/* client identifier == xid ? */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, xid, 1, 0),
		/* ignore */
		BPF_STMT(BPF_RET + BPF_K, 0),
		/* A <- MAC address length */
		BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
				offsetof(struct dhcp_packet, dhcp.hlen)),
		/* address length == dhcp_hlen ? */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_ALEN, 1, 0),
		/* ignore */
		BPF_STMT(BPF_RET + BPF_K, 0),
		/* A <- DHCP magic cookie */
		BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
				offsetof(struct dhcp_packet, dhcp.magic)),
		/* cookie == DHCP magic cookie ? */
		BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, DHCP_MAGIC, 1, 0),
		/* ignore */
		BPF_STMT(BPF_RET + BPF_K, 0),
		/* return all */
		BPF_STMT(BPF_RET + BPF_K, 65535),
	};
	const struct sock_fprog fprog = {
		.len = L_ARRAY_SIZE(filter),
		.filter = filter
	};

	s = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (s < 0)
		return -errno;

	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER,
						&fprog, sizeof(fprog)) < 0)
		goto error;

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_IP);
	addr.sll_ifindex = ifindex;
	addr.sll_halen = ETH_ALEN;
	memset(addr.sll_addr, 0xff, ETH_ALEN);

	if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		goto error;

	return s;

error:
	TEMP_FAILURE_RETRY(close(s));
	return -errno;
}

static int _dhcp_default_transport_open(struct dhcp_transport *s, uint32_t xid)
{
	struct dhcp_default_transport *transport =
		l_container_of(s, struct dhcp_default_transport, super);
	int fd;

	if (transport->io)
		return -EALREADY;

	fd = kernel_raw_socket_open(s->ifindex, transport->port, xid);
	if (fd < 0)
		return fd;

	transport->io = l_io_new(fd);
	l_io_set_close_on_destroy(transport->io, true);
	l_io_set_read_handler(transport->io,
					_dhcp_default_transport_read_handler,
					transport, NULL);

	return 0;
}

static void _dhcp_default_transport_close(struct dhcp_transport *s)
{
	struct dhcp_default_transport *transport =
		l_container_of(s, struct dhcp_default_transport, super);

	l_io_destroy(transport->io);
	transport->io = NULL;

	if (transport->udp_fd >= 0) {
		TEMP_FAILURE_RETRY(close(transport->udp_fd));
		transport->udp_fd = -1;
	}
}

struct dhcp_transport *_dhcp_default_transport_new(uint32_t ifindex,
							const char *ifname,
							uint16_t port)
{
	struct dhcp_default_transport *transport;
	transport = l_new(struct dhcp_default_transport, 1);

	transport->super.open = _dhcp_default_transport_open;
	transport->super.bind = _dhcp_default_transport_bind;
	transport->super.close = _dhcp_default_transport_close;
	transport->super.send = _dhcp_default_transport_send;
	transport->super.broadcast = _dhcp_default_transport_broadcast;

	transport->super.ifindex = ifindex;
	l_strlcpy(transport->ifname, ifname, IFNAMSIZ);
	transport->port = port;

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
