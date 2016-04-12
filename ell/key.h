/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2016  Intel Corporation. All rights reserved.
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

#ifndef __ELL_KEY_H
#define __ELL_KEY_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>

struct l_key;

enum l_key_type {
	L_KEY_RAW = 0,
	L_KEY_ASYMMETRIC
};

struct l_key *l_key_new(enum l_key_type type, const void *payload,
			size_t payload_length);

void l_key_free(struct l_key *key);

bool l_key_update(struct l_key *key, const void *payload, size_t len);

bool l_key_extract(struct l_key *key, void *payload, size_t *len);

ssize_t l_key_get_size(struct l_key *key);

bool l_key_compute_dh_public(struct l_key *generator, struct l_key *private,
			     struct l_key *prime, void *payload, size_t *len);

bool l_key_compute_dh_secret(struct l_key *other_public, struct l_key *private,
			     struct l_key *prime, void *payload, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* __ELL_KEY_H */
