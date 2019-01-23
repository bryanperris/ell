/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
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

#ifndef __ELL_TIME_H
#define __ELL_TIME_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <limits.h>

uint64_t l_time_now(void);

static inline bool l_time_after(uint64_t a, uint64_t b)
{
	if ((int64_t)(b - a) < 0)
		return true;

	return false;
}

static inline bool l_time_before(uint64_t a, uint64_t b)
{
	return l_time_after(b, a);
}

static inline uint64_t l_time_offset(uint64_t time, uint64_t offset)
{
	/* check overflow */
	if ((int64_t)(time + offset) <= 0)
		return ULONG_MAX;

	return time + offset;
}

static inline uint64_t l_time_diff(uint64_t a, uint64_t b)
{
	return (a < b) ? b - a : a - b;
}

#ifdef __cplusplus
}
#endif

#endif /* __ELL_TIME_H */
