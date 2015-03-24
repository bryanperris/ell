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
#include <stdio.h>
#include <linux/genetlink.h>
#include <ell/ell.h>

#include "ell/genl-private.h"

static bool do_print = false;

static void do_debug(const char *str, void *user_data)
{
	const char *prefix = user_data;

	printf("%s%s\n", prefix, str);
}

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

static void build_set_station(const void *data)
{
	static uint32_t index = 3;
	static const unsigned char mac[6] =
		{ 0x24, 0xa2, 0xe1, 0xec, 0x17, 0x04 };
	static uint32_t flags[] = { 2, 2 };
	struct l_genl_msg *msg;
	const void *raw;
	size_t size;

	msg = l_genl_msg_new_sized(18, 512);
	assert(msg);

	assert(l_genl_msg_append_attr(msg, 3, 4, &index));
	assert(l_genl_msg_append_attr(msg, 6, 6, mac));
	assert(l_genl_msg_append_attr(msg, 67, 8, flags));

	raw = _genl_msg_as_bytes(msg, 0x17, 0x05, 0x550d538b, 3604, &size);

	if (do_print) {
		l_util_hexdump(false, raw, size, do_debug, "[MSG] ");
		l_util_hexdump(true, set_station_request, size,
					do_debug, "[MSG] ");
	}

	assert(size == sizeof(set_station_request));
	assert(!memcmp(raw, set_station_request, size));

	l_genl_msg_unref(msg);
}

static const unsigned char set_rekey_offload_request[] = {
	0x54, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x05, 0x00, 0x59, 0xa3, 0xe1, 0x53,
	0xba, 0x02, 0x40, 0xe7, 0x4f, 0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00,
	0x03, 0x00, 0x00, 0x00, 0x38, 0x00, 0x7a, 0x00, 0x14, 0x00, 0x01, 0x00,
	0x2f, 0x82, 0xbb, 0x0d, 0x93, 0x56, 0x60, 0x4b, 0xb1, 0x55, 0x1c, 0x85,
	0xc0, 0xeb, 0x32, 0x8b, 0x14, 0x00, 0x02, 0x00, 0x43, 0x25, 0xcf, 0x08,
	0x0b, 0x92, 0xa7, 0x2d, 0x86, 0xdc, 0x43, 0x21, 0xd6, 0x0c, 0x12, 0x03,
	0x0c, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
};

static void parse_set_rekey_offload(const void *data)
{
	static const unsigned char kek[] = {
		0x2f, 0x82, 0xbb, 0x0d, 0x93, 0x56, 0x60, 0x4b,
		0xb1, 0x55, 0x1c, 0x85, 0xc0, 0xeb, 0x32, 0x8b };
	static const unsigned char kck[] = {
		0x43, 0x25, 0xcf, 0x08, 0x0b, 0x92, 0xa7, 0x2d,
		0x86, 0xdc, 0x43, 0x21, 0xd6, 0x0c, 0x12, 0x03 };
	static const unsigned char replay_counter[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	struct nlmsghdr *nlmsg;
	struct l_genl_msg *msg;
	struct l_genl_attr attr;
	struct l_genl_attr nested;
	bool result;
	uint16_t type;
	uint16_t len;
	const void *payload;

	nlmsg = (struct nlmsghdr *) set_rekey_offload_request;
	msg = _genl_msg_create(nlmsg);
	assert(msg);

	result = l_genl_attr_init(&attr, msg);
	assert(result);

	/*Interface Index: 3 (0x00000003) */
	assert(l_genl_attr_next(&attr, &type, &len, &payload));
	assert(type == 3);
	assert(len == 4);
	assert(*((unsigned int *) payload) == 3);

	/*
	 * Rekey Data: len 52
	 *     KEK: len 16
	 *         2f 82 bb 0d 93 56 60 4b b1 55 1c 85 c0 eb 32 8b
	 *     KCK: len 16
	 *         43 25 cf 08 0b 92 a7 2d 86 dc 43 21 d6 0c 12 03
	 *     Replay CTR: len 8
	 *         00 00 00 00 00 00 00 01
	 */
	assert(l_genl_attr_next(&attr, &type, &len, &payload));
	assert(type == 122);
	assert(len == 52);

	assert(l_genl_attr_recurse(&attr, &nested));

	assert(l_genl_attr_next(&nested, &type, &len, &payload));
	assert(type == 1);
	assert(len == 16);
	assert(!memcmp(payload, kek, 16));

	assert(l_genl_attr_next(&nested, &type, &len, &payload));
	assert(type == 2);
	assert(len == 16);
	assert(!memcmp(payload, kck, 16));

	assert(l_genl_attr_next(&nested, &type, &len, &payload));
	assert(type == 3);
	assert(len == 8);
	assert(!memcmp(payload, replay_counter, 8));

	l_genl_msg_unref(msg);
}

int main(int argc, char *argv[])
{
	l_test_add("Parse Set Station Request", parse_set_station, NULL);
	l_test_add("Parse Set Rekey Offload Request",
				parse_set_rekey_offload, NULL);

	l_test_add("Build Set Station Request", build_set_station, NULL);

	return l_test_run();
}
