/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __ELL_UTIL_H
#define __ELL_UTIL_H

#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#define L_PTR_TO_UINT(p) ((unsigned int) ((uintptr_t) (p)))
#define L_UINT_TO_PTR(u) ((void *) ((uintptr_t) (u)))

#define L_PTR_TO_INT(p) ((int) ((intptr_t) (p)))
#define L_INT_TO_PTR(u) ((void *) ((intptr_t) (u)))

void *l_malloc(size_t size);
void l_free(void *ptr);

void *l_realloc(void *mem, size_t size);

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

char *l_strdup_printf(const char *format, ...);

char *l_util_hexstring(const unsigned char *buf, size_t len);

typedef void (*l_util_hexdump_func_t) (const char *str, void *user_data);

void l_util_hexdump(bool in, const unsigned char *buf, size_t len,
			l_util_hexdump_func_t function, void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_UTIL_H */
