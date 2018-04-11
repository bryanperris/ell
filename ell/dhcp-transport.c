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
#include <sys/uio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>

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

static int kernel_socket_open(uint32_t ifindex,
					const char *ifname, uint32_t port)
{
	int s;
	int err;
	int one = 1;
	struct sockaddr_in saddr;

	s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
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
	close(s);
	return -errno;
}

static int _dhcp_default_transport_open(struct dhcp_transport *s,
					uint32_t ifindex, const char *ifname,
					uint32_t port)
{
	struct dhcp_default_transport *transport =
		container_of(s, struct dhcp_default_transport, super);
	int fd;

	if (transport->io)
		return -EALREADY;

	fd = kernel_socket_open(ifindex, ifname, port);
	if (fd < 0)
		return fd;

	transport->io = l_io_new(fd);
	l_io_set_close_on_destroy(transport->io, true);

	return 0;
}

static int _dhcp_default_transport_send(struct dhcp_transport *s,
					const struct sockaddr_in *dest,
					const void *data, size_t len)
{
	struct dhcp_default_transport *transport =
		container_of(s, struct dhcp_default_transport, super);
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
		container_of(s, struct dhcp_default_transport, super);

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
