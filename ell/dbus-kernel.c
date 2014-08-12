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

#include <stdio.h>
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

#define DEFAULT_BLOOM_SIZE (512 / 8)
#define DEFAULT_BLOOM_N_HASH (8)

#define HASH_KEY(v0,v1,v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15) \
        { 0x##v0, 0x##v1, 0x##v2, 0x##v3, 0x##v4, 0x##v5, 0x##v6, 0x##v7, \
	0x##v8, 0x##v9, 0x##v10, 0x##v11, 0x##v12, 0x##v13, 0x##v14, 0x##v15 }

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
	bus_make.head.size = sizeof(bus_make.head) +
				bus_make.bloom_size + bus_make.name_size;
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
	size += align_len(offsetof(struct kdbus_item, str) + len + 1, 8);

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
