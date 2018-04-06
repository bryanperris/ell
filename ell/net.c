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

#include <linux/if_arp.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "net.h"
#include "private.h"

/**
 * SECTION:net
 * @short_description: Network Interface related utilities
 *
 * Network Interface utilities
 */

/**
 * l_net_get_mac_address:
 * @ifindex: Interface index to query
 * @out_addr: Buffer to copy the mac address to.  Must be able to hold 6 bytes
 *
 * Obtains the mac address of the network interface given by @ifindex
 *
 * Returns: #true on success and #false on failure
 **/
LIB_EXPORT bool l_net_get_mac_address(uint32_t ifindex, uint8_t *out_addr)
{
	struct ifreq ifr;
	int sk, err;

	sk = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return false;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ifindex;

	err = ioctl(sk, SIOCGIFNAME, &ifr);
	if (err < 0)
		goto error;

	err = ioctl(sk, SIOCGIFHWADDR, &ifr);
	if (err < 0)
		goto error;

	close(sk);

	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
		return false;

	memcpy(out_addr, ifr.ifr_hwaddr.sa_data, 6);
	return true;

error:
	close(sk);
	return false;
}
