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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <alloca.h>
#include <errno.h>
#include <sys/mman.h>

#include "linux/kdbus.h"

#include "private.h"
#include "dbus.h"
#include "dbus-private.h"
#include "siphash-private.h"

#define KDBUS_ITEM_HEADER_SIZE offsetof(struct kdbus_item, data)
#define KDBUS_POOL_SIZE (16*1024*1024)

#define KDBUS_ITEM_FOREACH(item, head, first)				\
	for (item = head->first;					\
		(void *)(item) < (void *)(head) + (head)->size;		\
		item = KDBUS_ITEM_NEXT(item))				\

#define DEFAULT_BLOOM_SIZE (512 / 8)
#define DEFAULT_BLOOM_N_HASH (8)

#define HASH_KEY(v0,v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15) \
        { 0x##v0, 0x##v1, 0x##v2, 0x##v3, 0x##v4, 0x##v5, 0x##v6, 0x##v7, \
	0x##v8, 0x##v9, 0x##v10, 0x##v11, 0x##v12, 0x##v13, 0x##v14, 0x##v15 }

static inline size_t KDBUS_ITEM_SIZE(size_t actual)
{
	return align_len(actual + offsetof(struct kdbus_item, data), 8);
}

static inline struct kdbus_item *KDBUS_ITEM_NEXT(struct kdbus_item *item)
{
	size_t aligned = align_len(item->size, 8);
	void *start = item;

	return start + aligned;
}

static inline unsigned int __u64_log2(uint64_t n)
{
	if (n == 0)
		return 0;

	return __builtin_clzll(n) ^ 63U;
}

static inline void set_bit(uint64_t filter[], size_t b)
{
	filter[b >> 6] |= 1ULL << (b & 63);
}

static const uint8_t hash_keys[][16] = {
	HASH_KEY(b9,66,0b,f0,46,70,47,c1,88,75,c4,9c,54,b9,bd,15),
	HASH_KEY(aa,a1,54,a2,e0,71,4b,39,bf,e1,dd,2e,9f,c5,4a,3b),
	HASH_KEY(63,fd,ae,be,cd,82,48,12,a1,6e,41,26,cb,fa,a0,c8),
	HASH_KEY(23,be,45,29,32,d2,46,2d,82,03,52,28,fe,37,17,f5),
	HASH_KEY(56,3b,bf,ee,5a,4f,43,39,af,aa,94,08,df,f0,fc,10),
	HASH_KEY(31,80,c8,73,c7,ea,46,d3,aa,25,75,0f,9e,4c,09,29),
	HASH_KEY(7d,f7,18,4b,7b,a4,44,d5,85,3c,06,e0,65,53,96,6d),
	HASH_KEY(f2,77,e9,6f,93,b5,4e,71,9a,0c,34,88,39,25,bf,35),
};

static void bloom_update(uint64_t filter[], size_t size, uint8_t num_hash,
				const void *data, size_t data_size)
{
	uint8_t hashed[8];
	uint64_t n_bits;
	unsigned int index_size;
	unsigned int i;
	unsigned int hash_index;
	unsigned int unused_bytes = 0;

	if (unlikely(num_hash == 0))
		return;

	if (unlikely(size == 0))
		return;

	n_bits = size * 8;
	index_size = (__u64_log2(n_bits) + 7) / 8;

	if (unlikely(index_size > sizeof(uint32_t)))
		return;

	for (i = 0, hash_index = 0; i < num_hash; i++) {
		uint32_t index = 0;
		unsigned int j;

		for (j = 0; j < index_size; j++) {
			if (unused_bytes == 0) {
				_siphash24(hashed, data, data_size,
						hash_keys[hash_index++]);
				unused_bytes = 8;
			}

			index = index << 8;
			index |= hashed[8 - unused_bytes];
			unused_bytes -= 1;
		}

		index &= n_bits - 1;
		set_bit(filter, index);
	}
}

void _dbus_kernel_bloom_add(uint64_t filter[], size_t size, uint8_t num_hash,
				const char *prefix, const char *str)
{
	char *buf;
	size_t len;

	len = strlen(prefix) + 1 + strlen(str) + 1;
	buf = alloca(len);

	sprintf(buf, "%s:%s", prefix, str);

	bloom_update(filter, size, num_hash, buf, len - 1);
}

void _dbus_kernel_bloom_add_parents(uint64_t filter[], size_t size,
					uint8_t num_hash, const char *prefix,
					const char *str, const char sep)
{
	char *buf;
	size_t len;
	int start;

	len = strlen(prefix) + 1 + strlen(str) + 1;
	buf = alloca(len);

	sprintf(buf, "%s:%n%s", prefix, &start, str);

	while (true) {
		char *s = strrchr(buf + start, sep);

		if (!s)
			break;

		if (s == buf + start)
			break;

		*s = '\0';
		bloom_update(filter, size, num_hash, buf, s - buf);
	}
}

int _dbus_kernel_create_bus(const char *name)
{
	struct {
		struct kdbus_cmd_make head;
		/* bloom size item */
		uint64_t bloom_size;
		uint64_t bloom_type;
		struct kdbus_bloom_parameter bloom_param;
		/* name item */
		uint64_t name_size;
		uint64_t name_type;
		char name_param[64];
	} bus_make;
	int fd;

	fd = open("/dev/kdbus/control", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return -1;

	memset(&bus_make, 0, sizeof(bus_make));
	/* bloom size item */
	bus_make.bloom_size = KDBUS_ITEM_HEADER_SIZE +
					sizeof(bus_make.bloom_param);
	bus_make.bloom_type = KDBUS_ITEM_BLOOM_PARAMETER;
	bus_make.bloom_param.size = DEFAULT_BLOOM_SIZE;
	bus_make.bloom_param.n_hash = DEFAULT_BLOOM_N_HASH;
	/* name item */
	snprintf(bus_make.name_param, sizeof(bus_make.name_param), "%s", name);
	bus_make.name_size = KDBUS_ITEM_HEADER_SIZE +
				strlen(bus_make.name_param) + 1;
	bus_make.name_type = KDBUS_ITEM_MAKE_NAME;
	/* bus make head */
	bus_make.head.size = align_len(sizeof(bus_make.head) +
					bus_make.bloom_size +
					bus_make.name_size, 8);
	bus_make.head.flags = KDBUS_MAKE_ACCESS_WORLD;

	if (ioctl(fd, KDBUS_CMD_BUS_MAKE, &bus_make) < 0) {
		close(fd);
		return -1;
        }

	return fd;
}

void _dbus_kernel_unmap_pool(void *pool)
{
	munmap(pool, KDBUS_POOL_SIZE);
}

int _dbus_kernel_hello(int fd, const char *connection_name,
			size_t *bloom_size, uint8_t *bloom_n_hash,
			uint64_t *id, void **pool, char **guid)
{
	size_t len = strlen(connection_name);
	size_t size;
	struct kdbus_cmd_hello *hello;
	struct kdbus_item *item;
	int ret;

	size = align_len(sizeof(struct kdbus_cmd_hello), 8);
	size += KDBUS_ITEM_SIZE(len + 1);

	hello = alloca(size);
	memset(hello, 0, size);

	hello->size = size;
	hello->conn_flags |= KDBUS_HELLO_ACCEPT_FD;
	hello->attach_flags |= KDBUS_ATTACH_NAMES;
	hello->pool_size = KDBUS_POOL_SIZE;

	item = hello->items;
	item->size = KDBUS_ITEM_HEADER_SIZE + len + 1;
	item->type = KDBUS_ITEM_CONN_NAME;
	strcpy(item->str, connection_name);

	ret = ioctl(fd, KDBUS_CMD_HELLO, hello);
	if (ret < 0)
		return -errno;

        /* Check for incompatible flags (upper 32 bits) */
        if (hello->bus_flags > 0xFFFFFFFFULL ||
			hello->conn_flags > 0xFFFFFFFFULL)
                return -ENOTSUP;

	*pool = mmap(NULL, KDBUS_POOL_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	if (*pool == MAP_FAILED) {
		*pool = NULL;
		return -errno;
	}

	*bloom_size = hello->bloom.size;
	*bloom_n_hash = hello->bloom.n_hash;
	*id = hello->id;
	*guid = l_strdup_printf("%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
				"%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
				"%02hhx%02hhx",
				hello->id128[0], hello->id128[1],
				hello->id128[2], hello->id128[3],
				hello->id128[4], hello->id128[5],
				hello->id128[6], hello->id128[7],
				hello->id128[8], hello->id128[9],
				hello->id128[10], hello->id128[11],
				hello->id128[12], hello->id128[13],
				hello->id128[14], hello->id128[15]);

	return 0;
}

int _dbus_kernel_send(int fd, size_t bloom_size, uint8_t bloom_n_hash,
			struct l_dbus_message *message)
{
	size_t kmsg_size;
	bool unique;
	uint64_t uninitialized_var(id);
	const char *dest;
	size_t dest_len;
	struct kdbus_item *item;
	void *header;
	size_t header_size;
	void *body;
	size_t body_size;
	int ret;
	L_AUTO_FREE_VAR(struct kdbus_msg *, kmsg);

	dest = l_dbus_message_get_destination(message);
	if (dest)
		unique = _dbus_parse_unique_name(dest, &id);
	else
		unique = false;

	dest_len = dest ? strlen(dest) : 0;

	kmsg_size = sizeof(struct kdbus_msg);

	/* Reserve space for header + body */
	kmsg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));
	kmsg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_vec));

	/* Reserve space for bloom filter */
	if (_dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_SIGNAL)
		kmsg_size += KDBUS_ITEM_SIZE(sizeof(struct kdbus_bloom_filter) +
						bloom_size);

	/* Reserve space for well-known destination header */
	if (dest && !unique)
		kmsg_size += KDBUS_ITEM_SIZE(dest_len + 1);

	kmsg = aligned_alloc(8, kmsg_size);
	if (!kmsg)
		return -ENOMEM;

	memset(kmsg, 0, kmsg_size);
	item = kmsg->items;

	kmsg->payload_type = KDBUS_PAYLOAD_DBUS;
	kmsg->priority = 0;
	kmsg->cookie = _dbus_message_get_serial(message);

	if (l_dbus_message_get_no_autostart(message))
		kmsg->flags |= KDBUS_MSG_FLAGS_NO_AUTO_START;

	if (!l_dbus_message_get_no_reply(message))
		kmsg->flags |= KDBUS_MSG_FLAGS_EXPECT_REPLY;

	if (!unique && dest) {
		kmsg->dst_id = KDBUS_DST_ID_NAME;
		item->size = KDBUS_ITEM_HEADER_SIZE + dest_len + 1;
		item->type = KDBUS_ITEM_DST_NAME;
		strcpy(item->str, dest);
		item = KDBUS_ITEM_NEXT(item);
	} else if (!unique && !dest)
		kmsg->dst_id = KDBUS_DST_ID_BROADCAST;
	else
		kmsg->dst_id = id;

	switch(_dbus_message_get_type(message)) {
	case DBUS_MESSAGE_TYPE_METHOD_RETURN:
	case DBUS_MESSAGE_TYPE_ERROR:
	{
		uint32_t reply_cookie = _dbus_message_get_reply_serial(message);

		if (reply_cookie == 0)
			return -EINVAL;

		kmsg->cookie_reply = reply_cookie;
		break;
	}
	case DBUS_MESSAGE_TYPE_METHOD_CALL:
		kmsg->timeout_ns = 30000 * 1000ULL;
		break;
	case DBUS_MESSAGE_TYPE_SIGNAL:
		item->size = KDBUS_ITEM_HEADER_SIZE +
				sizeof(struct kdbus_bloom_filter) + bloom_size;
		item->type = KDBUS_ITEM_BLOOM_FILTER;

		item->bloom_filter.generation = 0;
		_dbus_kernel_calculate_bloom(message,
					(uint64_t *) item->bloom_filter.data,
					bloom_size, bloom_n_hash);

		item = KDBUS_ITEM_NEXT(item);
		break;
	}

	header = _dbus_message_get_header(message, &header_size);
	item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
	item->type = KDBUS_ITEM_PAYLOAD_VEC;
	item->vec.address = (uintptr_t) header;
	item->vec.size = header_size;
	item = KDBUS_ITEM_NEXT(item);

	body = _dbus_message_get_body(message, &body_size);
	if (body_size > 0) {
		item->size = KDBUS_ITEM_HEADER_SIZE + sizeof(struct kdbus_vec);
		item->type = KDBUS_ITEM_PAYLOAD_VEC;
		item->vec.address = (uintptr_t) body;
		item->vec.size = body_size;
		item = KDBUS_ITEM_NEXT(item);
	}

	kmsg->size = (void *)item - (void *)kmsg;

	ret = ioctl(fd, KDBUS_CMD_MSG_SEND, kmsg);
	if (ret < 0)
		return -errno;

	return 0;
}

static int collect_body_parts(struct kdbus_msg *kmsg,
					size_t header_size, void **out_header,
					size_t body_size, void **out_body)
{
	struct kdbus_item *item;
	void *body;
	void *header;
	bool saw_header = false;
	size_t offset = 0;

	header = l_malloc(header_size);
	if (!header)
		return -ENOMEM;

	body = NULL;

	if (body_size > 0) {
		body = l_malloc(body_size);
		if (!body) {
			l_free(header);
			return -ENOMEM;
		}
	}

	KDBUS_ITEM_FOREACH(item, kmsg, items) {
		switch (item->type) {
		case KDBUS_ITEM_PAYLOAD_OFF:
			if (saw_header) {
				memcpy(body + offset,
					(void *)kmsg + item->vec.offset,
					item->vec.size);

				offset += item->vec.size;
			} else {
				memcpy(header, (void *)kmsg + item->vec.offset,
					item->vec.size);
				saw_header = true;
			}

			break;
		}
	}

	*out_body = body;
	*out_header = header;

	return 0;
}

static int _dbus_kernel_make_message(struct kdbus_msg *kmsg,
				struct l_dbus_message **out_message)
{
	struct kdbus_item *item;
	void *header = 0;
	size_t header_size = 0;
	struct dbus_header *hdr;
	void *body = 0;
	size_t body_size = 0;
	int r;
	const char *destination = 0;
	char unique_bus_name[128];

	KDBUS_ITEM_FOREACH(item, kmsg, items) {
		switch (item->type) {
		case KDBUS_ITEM_PAYLOAD_OFF:
			if (!header_size) {
				header = (void *)kmsg + item->vec.offset;

				header_size = item->vec.size;

				if (!_dbus_header_is_valid(header, header_size))
					return -EBADMSG;
			} else
				body_size += item->vec.size;

			break;
		case KDBUS_ITEM_PAYLOAD_MEMFD:
			if (!header_size)
				return -EBADMSG;

			return -ENOTSUP;
		case KDBUS_ITEM_FDS:
			return -ENOTSUP;
		case KDBUS_ITEM_DST_NAME:
			if (!_dbus_valid_bus_name(item->str))
				return -EBADMSG;

			destination = item->str;
			break;
		}
	}

	if (!header)
		return -EBADMSG;

	hdr = header;
	if (hdr->endian != DBUS_NATIVE_ENDIAN)
		return -EPROTOTYPE;

	if (hdr->version != 2)
		return -EPROTO;

	if (hdr->body_length != body_size)
		return -EBADMSG;

	r = collect_body_parts(kmsg, header_size, &header,
						body_size, &body);
	if (r < 0)
		return r;

	*out_message = dbus_message_build(header, header_size, body, body_size,
						NULL, 0);

	if (kmsg->src_id != KDBUS_SRC_ID_KERNEL) {
		sprintf(unique_bus_name, ":1.%llu", kmsg->src_id);
		_dbus_message_set_sender(*out_message, unique_bus_name);
	} else
		_dbus_message_set_sender(*out_message, "org.freedesktop.DBus");

	switch (kmsg->dst_id) {
	case KDBUS_DST_ID_NAME:
		break;
	case KDBUS_DST_ID_BROADCAST:
		break;
	default:
		sprintf(unique_bus_name, ":1.%llu", kmsg->dst_id);
		_dbus_message_set_destination(*out_message, unique_bus_name);
	}

	if (destination)
		_dbus_message_set_destination(*out_message, destination);

	return 0;
}

int _dbus_kernel_recv(int fd, void *kdbus_pool,
				struct l_dbus_message **out_message)
{
	struct kdbus_cmd_recv recv_cmd;
	struct kdbus_msg *msg;
	int r;

	memset(&recv_cmd, 0, sizeof(recv_cmd));

	r = ioctl(fd, KDBUS_CMD_MSG_RECV, &recv_cmd);
	if (r < 0)
		return -errno;

	msg = (struct kdbus_msg *)(kdbus_pool + recv_cmd.offset);

	switch (msg->payload_type) {
	case KDBUS_PAYLOAD_DBUS:
		r = _dbus_kernel_make_message(msg, out_message);
		break;
	case KDBUS_PAYLOAD_KERNEL:
		break;
	default:
		r = -EPROTONOSUPPORT;
		break;
	}

	ioctl(fd, KDBUS_CMD_FREE, &recv_cmd.offset);

	return r;
}

int _dbus_kernel_name_acquire(int fd, const char *name)
{
	struct {
		struct kdbus_cmd_name head;
		char param[64];
	} cmd_name;
	size_t nlen;

	if (!name)
		return false;

	nlen = strlen(name) + 1;
	if (nlen > sizeof(cmd_name.param))
		return false;

	memset(&cmd_name, 0, sizeof(cmd_name));

	strcpy(cmd_name.param, name);
	cmd_name.head.size = sizeof(cmd_name.head) + nlen;

	if (ioctl(fd, KDBUS_CMD_NAME_ACQUIRE, &cmd_name) < 0)
		return -errno;

	return 0;
}

int _dbus_kernel_add_match(int fd, uint64_t bloom_size, uint64_t bloom_n_hash,
				uint64_t *out_cookie)
{
	static uint64_t cookie = 1;
	struct kdbus_item *item;
	struct kdbus_cmd_match *cmd;
	size_t cmd_size;
	int r;

	cmd_size = sizeof(struct kdbus_cmd_match);
	cmd_size += KDBUS_ITEM_SIZE(bloom_size);

	cmd = alloca(cmd_size);
	memset(cmd, 0, cmd_size);
	cmd->size = cmd_size;
	cmd->cookie = cookie++;
	item = cmd->items;

	item->size = KDBUS_ITEM_HEADER_SIZE + bloom_size;
	item->type = KDBUS_ITEM_BLOOM_MASK;
	_dbus_kernel_bloom_add((uint64_t *) item->data64, bloom_size,
				bloom_n_hash, "message-type", "signal");
	item = KDBUS_ITEM_NEXT(item);

	r = ioctl(fd, KDBUS_CMD_MATCH_ADD, cmd);
	if (r < 0)
		return -errno;

	if (out_cookie)
		*out_cookie = cmd->cookie;

	return 0;
}

int _dbus_kernel_remove_match(int fd, uint64_t cookie)
{
	struct kdbus_cmd_match cmd;
	int r;

	memset(&cmd, 0, sizeof(cmd));
	cmd.size = sizeof(cmd);
	cmd.cookie = cookie;

	r = ioctl(fd, KDBUS_CMD_MATCH_REMOVE, &cmd);
	if (r < 0)
		return -errno;

	return 0;
}
