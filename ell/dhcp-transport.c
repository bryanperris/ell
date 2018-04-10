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

#include "private.h"
#include "dhcp-private.h"

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
