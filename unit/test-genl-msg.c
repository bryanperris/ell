/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2014  Intel Corporation. All rights reserved.
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

#include <assert.h>
#include <linux/genetlink.h>
#include <ell/ell.h>

#include "ell/genl-private.h"

static unsigned char set_station_request[] = {
	0x34, 0x00, 0x00, 0x00, 0x17, 0x00, 0x05, 0x00, 0x8b, 0x53, 0x0d, 0x55,
	0x14, 0x0e, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x06, 0x00, 0x24, 0xa2, 0xe1, 0xec,
	0x17, 0x04, 0x00, 0x00, 0x0c, 0x00, 0x43, 0x00, 0x02, 0x00, 0x00, 0x00,
	0x02, 0x00, 0x00, 0x00,
};

static void parse_set_station(const void *data)
{
	static const unsigned char mac[6] =
		{ 0x24, 0xa2, 0xe1, 0xec, 0x17, 0x04 };
	struct nlmsghdr *nlmsg;
	struct l_genl_msg *msg;
	struct l_genl_attr attr;
	bool result;
	uint16_t type;
	uint16_t len;
	const void *payload;

	nlmsg = (struct nlmsghdr *) set_station_request;
	msg = _genl_msg_create(nlmsg);
	assert(msg);

	result = l_genl_attr_init(&attr, msg);
	assert(result);

	/*Interface Index: 3 (0x00000003) */
	assert(l_genl_attr_next(&attr, &type, &len, &payload));
	assert(type == 3);
	assert(len == 4);
	assert(*((unsigned int *) payload) == 3);

	/* MAC Address 24:A2:E1:EC:17:04 */
	assert(l_genl_attr_next(&attr, &type, &len, &payload));
	assert(type == 6);
	assert(len == 6);
	assert(!memcmp(payload, mac, 6));

	/* Station Flags 2: len 8
	 *     Mask: 0x00000002
	 *         Authorized
	 *     Set: 0x00000002
	 *         Authorized
	 */
	assert(l_genl_attr_next(&attr, &type, &len, &payload));
	assert(type == 67);
	assert(len == 8);
	assert(((unsigned int *) payload)[0] == 2);
	assert(((unsigned int *) payload)[1] == 2);

	l_genl_msg_unref(msg);
}

int main(int argc, char *argv[])
{
	l_test_add("Parse Set Station Request", parse_set_station, NULL);

	return l_test_run();
}
