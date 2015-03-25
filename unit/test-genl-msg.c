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

	assert(l_genl_msg_get_command(msg) == 18);

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

	assert(l_genl_msg_get_command(msg) == 79);

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

static void build_set_rekey_offload(const void *data)
{
	static uint32_t index = 3;
	static const unsigned char kek[] = {
		0x2f, 0x82, 0xbb, 0x0d, 0x93, 0x56, 0x60, 0x4b,
		0xb1, 0x55, 0x1c, 0x85, 0xc0, 0xeb, 0x32, 0x8b };
	static const unsigned char kck[] = {
		0x43, 0x25, 0xcf, 0x08, 0x0b, 0x92, 0xa7, 0x2d,
		0x86, 0xdc, 0x43, 0x21, 0xd6, 0x0c, 0x12, 0x03 };
	static const unsigned char replay_counter[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	struct l_genl_msg *msg;
	const void *raw;
	size_t size;

	msg = l_genl_msg_new_sized(79, 512);
	assert(msg);

	assert(l_genl_msg_append_attr(msg, 3, 4, &index));

	assert(l_genl_msg_enter_nested(msg, 122));
	assert(l_genl_msg_append_attr(msg, 1, 16, kek));
	assert(l_genl_msg_append_attr(msg, 2, 16, kck));
	assert(l_genl_msg_append_attr(msg, 3, 8, replay_counter));
	assert(l_genl_msg_leave_nested(msg));

	raw = _genl_msg_as_bytes(msg, 0x1b, 0x05, 0x53e1a359, 0xe74002ba,
					&size);
	if (do_print) {
		l_util_hexdump(false, raw, size, do_debug, "[MSG] ");
		l_util_hexdump(true, set_rekey_offload_request, size,
					do_debug, "[MSG] ");
	}

	assert(size == sizeof(set_rekey_offload_request));
	assert(!memcmp(raw, set_rekey_offload_request, size));

	l_genl_msg_unref(msg);
}

/*
 * This example is generated by libnl:
	msg = nlmsg_alloc();
	hdr = genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, ops.o_id,
			0, 0, TASKSTATS_CMD_GET, TASKSTATS_GENL_VERSION);
	nla_put_u32(msg, TASKSTATS_CMD_ATTR_PID, 1);

	nest1 = nla_nest_start(msg, 0x45);
	nla_put_string(msg, 0x46, "f");
	nla_put_string(msg, 0x47, "foob");
	nla_put_string(msg, 0x48, "foobar");

	nest2 = nla_nest_start(msg, 0x49);
	nla_put_string(msg, 0x50, "ba");
	nla_nest_end(msg, nest2);
	nla_nest_end(msg, nest1);
*/

static const unsigned char libnl_nested[] = {
	0x4c, 0x00, 0x00, 0x00, 0x15, 0x00, 0x05, 0x00, 0x72, 0x05, 0x13, 0x55,
	0x77, 0x68, 0x40, 0x0c, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x01, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x30, 0x00, 0x45, 0x00, 0x06, 0x00, 0x46, 0x00,
	0x66, 0x00, 0x00, 0x00, 0x09, 0x00, 0x47, 0x00, 0x66, 0x6f, 0x6f, 0x62,
	0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x48, 0x00, 0x66, 0x6f, 0x6f, 0x62,
	0x61, 0x72, 0x00, 0x00, 0x0c, 0x00, 0x49, 0x00, 0x07, 0x00, 0x50, 0x00,
	0x62, 0x61, 0x00, 0x00,
};

static void parse_libnl_nested(const void *data)
{
	struct nlmsghdr *nlmsg;
	struct l_genl_msg *msg;
	struct l_genl_attr attr;
	struct l_genl_attr nested1;
	struct l_genl_attr nested2;
	bool result;
	uint16_t type;
	uint16_t len;
	const void *payload;

	nlmsg = (struct nlmsghdr *) libnl_nested;
	msg = _genl_msg_create(nlmsg);
	assert(msg);

	assert(l_genl_msg_get_command(msg) == 1);

	result = l_genl_attr_init(&attr, msg);
	assert(result);

	assert(l_genl_attr_next(&attr, &type, &len, &payload));
	assert(type == 1);
	assert(len == 4);
	assert(*((unsigned int *) payload) == 1);

	assert(l_genl_attr_next(&attr, &type, &len, &payload));
	assert(type == 0x45);
	assert(len == 44);

	assert(l_genl_attr_recurse(&attr, &nested1));

	assert(l_genl_attr_next(&nested1, &type, &len, &payload));
	assert(type == 0x46);
	assert(len == 2);
	assert(!strcmp(payload, "f"));

	assert(l_genl_attr_next(&nested1, &type, &len, &payload));
	assert(type == 0x47);
	assert(len == 5);
	assert(!strcmp(payload, "foob"));

	assert(l_genl_attr_next(&nested1, &type, &len, &payload));
	assert(type == 0x48);
	assert(len == 7);
	assert(!strcmp(payload, "foobar"));

	assert(l_genl_attr_next(&nested1, &type, &len, &payload));
	assert(type == 0x49);
	assert(len == 8);

	assert(l_genl_attr_recurse(&nested1, &nested2));
	assert(l_genl_attr_next(&nested2, &type, &len, &payload));
	assert(type == 0x50);
	assert(len == 3);
	assert(!strcmp(payload, "ba"));

	l_genl_msg_unref(msg);
}

static void build_libnl_nested(const void *data)
{
	static uint32_t index = 1;
	struct l_genl_msg *msg;
	const void *raw;
	size_t size;

	msg = l_genl_msg_new_sized(1, 512);
	assert(msg);

	assert(l_genl_msg_append_attr(msg, 1, 4, &index));

	assert(l_genl_msg_enter_nested(msg, 0x45));
	assert(l_genl_msg_append_attr(msg, 0x46, 2, "f"));
	assert(l_genl_msg_append_attr(msg, 0x47, 5, "foob"));
	assert(l_genl_msg_append_attr(msg, 0x48, 7, "foobar"));
	assert(l_genl_msg_enter_nested(msg, 0x49));
	assert(l_genl_msg_append_attr(msg, 0x50, 3, "ba"));
	assert(l_genl_msg_leave_nested(msg));
	assert(l_genl_msg_leave_nested(msg));

	raw = _genl_msg_as_bytes(msg, 0x15, 0x05, 0x55130572, 0x0c406877,
					&size);
	if (do_print) {
		l_util_hexdump(false, raw, size, do_debug, "[MSG] ");
		l_util_hexdump(true, libnl_nested, size, do_debug, "[MSG] ");
	}

	assert(size == sizeof(libnl_nested));
	assert(!memcmp(raw, libnl_nested, size));

	l_genl_msg_unref(msg);
}

int main(int argc, char *argv[])
{
	l_test_add("Parse Set Station Request", parse_set_station, NULL);
	l_test_add("Parse Set Rekey Offload Request",
				parse_set_rekey_offload, NULL);

	l_test_add("Build Set Station Request", build_set_station, NULL);
	l_test_add("Build Set Rekey Offload Request",
				build_set_rekey_offload, NULL);

	l_test_add("libnl-generated Example with Nesting",
				parse_libnl_nested, NULL);
	l_test_add("Build libnl-generated Example with Nesting",
				build_libnl_nested, NULL);

	return l_test_run();
}
