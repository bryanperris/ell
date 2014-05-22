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

#include <stdint.h>
#include <byteswap.h>

#include <ell/util.h>

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define align_len(len, boundary) (((len)+(boundary)-1) & ~((boundary)-1))

#define LIB_EXPORT __attribute__ ((visibility("default")))

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le16_to_cpu(val) (val)
#define le32_to_cpu(val) (val)
#define le64_to_cpu(val) (val)
#define cpu_to_le16(val) (val)
#define cpu_to_le32(val) (val)
#define cpu_to_le64(val) (val)
#define be16_to_cpu(val) bswap_16(val)
#define be32_to_cpu(val) bswap_32(val)
#define be64_to_cpu(val) bswap_64(val)
#define cpu_to_be16(val) bswap_16(val)
#define cpu_to_be32(val) bswap_32(val)
#define cpu_to_be64(val) bswap_64(val)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define le16_to_cpu(val) bswap_16(val)
#define le32_to_cpu(val) bswap_32(val)
#define le64_to_cpu(val) bswap_64(val)
#define cpu_to_le16(val) bswap_16(val)
#define cpu_to_le32(val) bswap_32(val)
#define cpu_to_le64(val) bswap_64(val)
#define be16_to_cpu(val) (val)
#define be32_to_cpu(val) (val)
#define be64_to_cpu(val) (val)
#define cpu_to_be16(val) (val)
#define cpu_to_be32(val) (val)
#define cpu_to_be64(val) (val)
#else
#error "Unknown byte order"
#endif

#define get_u8(ptr)		(*(uint8_t *) (ptr))
#define get_u16(ptr)		(*(uint16_t *) (ptr))
#define get_u32(ptr)		(*(uint32_t *) (ptr))
#define get_u64(ptr)		(*(uint64_t *) (ptr))
#define get_s16(ptr)		(*(int16_t *) (ptr))
#define get_s32(ptr)		(*(int32_t *) (ptr))
#define get_s64(ptr)		(*(int64_t *) (ptr))

#define get_unaligned(ptr)	L_GET_UNALIGNED(ptr)
#define put_unaligned(val, ptr)	L_PUT_UNALIGNED(val, ptr)

static inline uint16_t get_le16(const void *ptr)
{
	return le16_to_cpu(get_unaligned((const uint16_t *) ptr));
}

static inline uint16_t get_be16(const void *ptr)
{
	return be16_to_cpu(get_unaligned((const uint16_t *) ptr));
}

static inline uint32_t get_le32(const void *ptr)
{
	return le32_to_cpu(get_unaligned((const uint32_t *) ptr));
}

static inline uint32_t get_be32(const void *ptr)
{
	return be32_to_cpu(get_unaligned((const uint32_t *) ptr));
}

static inline uint64_t get_le64(const void *ptr)
{
	return le64_to_cpu(get_unaligned((const uint64_t *) ptr));
}

static inline uint64_t get_be64(const void *ptr)
{
	return be64_to_cpu(get_unaligned((const uint64_t *) ptr));
}

static inline void put_le16(uint16_t val, void *dst)
{
	put_unaligned(cpu_to_le16(val), (uint16_t *) dst);
}

static inline void put_be16(uint16_t val, const void *ptr)
{
	put_unaligned(cpu_to_be16(val), (uint16_t *) ptr);
}

static inline void put_le32(uint32_t val, void *dst)
{
	put_unaligned(cpu_to_le32(val), (uint32_t *) dst);
}

static inline void put_be32(uint32_t val, void *dst)
{
	put_unaligned(cpu_to_be32(val), (uint32_t *) dst);
}

struct l_debug_desc;

void debug_enable(struct l_debug_desc *start, struct l_debug_desc *stop);

void plugin_update_debug(void);

typedef void (*watch_event_cb_t) (int fd, uint32_t events, void *user_data);
typedef void (*watch_destroy_cb_t) (void *user_data);

typedef void (*idle_event_cb_t) (void *user_data);
typedef void (*idle_destroy_cb_t) (void *user_data);

int watch_add(int fd, uint32_t events, watch_event_cb_t callback,
				void *user_data, watch_destroy_cb_t destroy);
int watch_modify(int fd, uint32_t events);
int watch_remove(int fd);

int idle_add(idle_event_cb_t callback, void *user_data,
		idle_destroy_cb_t destroy);
void idle_remove(int id);
