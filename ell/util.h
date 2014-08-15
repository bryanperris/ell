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

#ifndef __ELL_UTIL_H
#define __ELL_UTIL_H

#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <byteswap.h>

#ifdef __cplusplus
extern "C" {
#endif

#define L_STRINGIFY(val) L_STRINGIFY_ARG(val)
#define L_STRINGIFY_ARG(contents) #contents

#define L_PTR_TO_UINT(p) ((unsigned int) ((uintptr_t) (p)))
#define L_UINT_TO_PTR(u) ((void *) ((uintptr_t) (u)))

#define L_PTR_TO_INT(p) ((int) ((intptr_t) (p)))
#define L_INT_TO_PTR(u) ((void *) ((intptr_t) (u)))

#define L_GET_UNALIGNED(ptr)			\
({						\
	struct __attribute__((packed)) {	\
		typeof(*(ptr)) __v;		\
	} *__p = (typeof(__p)) (ptr);		\
	__p->__v;				\
})

#define L_PUT_UNALIGNED(val, ptr)		\
do {						\
	struct __attribute__((packed)) {	\
		typeof(*(ptr)) __v;		\
	} *__p = (typeof(__p)) (ptr);		\
	__p->__v = (val);			\
} while(0)

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define L_LE16_TO_CPU(val) (val)
#define L_LE32_TO_CPU(val) (val)
#define L_LE64_TO_CPU(val) (val)
#define L_CPU_TO_LE16(val) (val)
#define L_CPU_TO_LE32(val) (val)
#define L_CPU_TO_LE64(val) (val)
#define L_BE16_TO_CPU(val) bswap_16(val)
#define L_BE32_TO_CPU(val) bswap_32(val)
#define L_BE64_TO_CPU(val) bswap_64(val)
#define L_CPU_TO_BE16(val) bswap_16(val)
#define L_CPU_TO_BE32(val) bswap_32(val)
#define L_CPU_TO_BE64(val) bswap_64(val)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define L_LE16_TO_CPU(val) bswap_16(val)
#define L_LE32_TO_CPU(val) bswap_32(val)
#define L_LE64_TO_CPU(val) bswap_64(val)
#define L_CPU_TO_LE16(val) bswap_16(val)
#define L_CPU_TO_LE32(val) bswap_32(val)
#define L_CPU_TO_LE64(val) bswap_64(val)
#define L_BE16_TO_CPU(val) (val)
#define L_BE32_TO_CPU(val) (val)
#define L_BE64_TO_CPU(val) (val)
#define L_CPU_TO_BE16(val) (val)
#define L_CPU_TO_BE32(val) (val)
#define L_CPU_TO_BE64(val) (val)
#else
#error "Unknown byte order"
#endif

#define L_AUTO_CLEANUP_VAR(vartype,varname,destroy) \
	vartype varname __attribute__((cleanup(destroy)));

#define L_AUTO_FREE_VAR(vartype,varname) \
	vartype varname __attribute__((cleanup(auto_free)));

#define L_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

void *l_malloc(size_t size) __attribute__ ((warn_unused_result, malloc));
void l_free(void *ptr);

void *l_realloc(void *mem, size_t size)
			__attribute__ ((warn_unused_result, malloc));

static inline void auto_free(void *a)
{
	void **p = (void **)a;
	l_free(*p);
}

/**
 * l_new:
 * @type: type of structure
 * @count: amount of structures
 *
 * Returns: pointer to allocated memory
 **/
#define l_new(type, count)			\
	(type *) (__extension__ ({		\
		size_t __n = (size_t) (count);	\
		size_t __s = sizeof(type);	\
		void *__p;			\
		__p = l_malloc(__n * __s);	\
		memset(__p, 0, __n * __s);	\
		__p;				\
	}))

char *l_strdup(const char *str);
char *l_strndup(const char *str, size_t max);
char *l_strdup_printf(const char *format, ...);
void l_strfreev(char **strlist);
char **l_strsplit(const char *str, const char sep);
char **l_strsplit_set(const char *str, const char *separators);
char *l_strjoinv(char **str_array, const char delim);

bool l_str_has_prefix(const char *str, const char *prefix);

char *l_util_hexstring(const unsigned char *buf, size_t len);

typedef void (*l_util_hexdump_func_t) (const char *str, void *user_data);

void l_util_hexdump(bool in, const void *buf, size_t len,
			l_util_hexdump_func_t function, void *user_data);
void l_util_hexdump_two(bool in, const void *buf1, size_t len1,
			const void *buf2, size_t len2,
			l_util_hexdump_func_t function, void *user_data);
void l_util_debug(l_util_hexdump_func_t function, void *user_data,
						const char *format, ...);

const char *l_util_get_debugfs_path(void);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_UTIL_H */
