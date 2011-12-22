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

#ifndef __ELL_CHECKSUM_H
#define __ELL_CHECKSUM_H

#ifdef __cplusplus
extern "C" {
#endif

struct l_checksum;

enum l_checksum_type {
	L_CHECKSUM_MD5,
	L_CHECKSUM_SHA1,
};

struct l_checksum *l_checksum_new(enum l_checksum_type type);
void l_checksum_free(struct l_checksum *checksum);

void l_checksum_update(struct l_checksum *checksum,
					const void *data, size_t len);
void l_checksum_get_digest(struct l_checksum *checksum,
					void *digest, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_CHECKSUM_H */
