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

#ifndef __ELL_PATH_H
#define __ELL_PATH_H

#ifdef __cplusplus
extern "C" {
#endif

const char *l_path_next(const char *path_str, char **ret);
char *l_path_find(const char *basename, const char *path_str, int mode);
uint64_t l_path_get_mtime(const char *path);
int l_path_touch(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_PATH_H */
