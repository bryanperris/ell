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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <time.h>

#include "time.h"
#include "private.h"

/**
 * l_time_now:
 *
 * Get the running clocktime in microseconds
 *
 * Returns: Current clock time in microseconds
 **/
LIB_EXPORT uint64_t l_time_now(void)
{
	struct timespec now;

	clock_gettime(CLOCK_BOOTTIME, &now);

	return now.tv_sec * 1000000 + now.tv_nsec / 1000;
}

/**
 * l_time_after
 *
 * Returns: True if time a is after time b
 **/

/**
 * l_time_before
 *
 * Returns: True if time a is before time b
 **/

/**
 * l_time_offset
 *
 * @time: Start time to calculate offset
 * @offset: Amount of time to add to 'time'
 *
 * Adds an offset to a time value. This checks for overflow, and if detected
 * returns UINT64_MAX.
 *
 * Returns: A time value 'time' + 'offset'. Or UINT64_MAX if time + offset
 * exceeds UINT64_MAX.
 **/
