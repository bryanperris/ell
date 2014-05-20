/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011-2012  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License version 2.1 as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
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
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>

#include "private.h"
#include "dbus-private.h"

#define DBUS_MAX_INTERFACE_LEN 255
#define DBUS_MAX_METHOD_LEN 255

static inline bool is_valid_character(const char c)
{
	if (c >= 'a' && c <= 'z')
		return true;

	if (c >= 'A' && c <= 'Z')
		return true;

	if (c >= '0' && c <= '9')
		return true;

	if (c == '_')
		return true;

	return false;
}

bool _dbus_valid_object_path(const char *path)
{
	unsigned int i;
	char c = '\0';

	if (path == NULL)
		return false;

	if (path[0] == '\0')
		return false;

	if (path[0] && !path[1] && path[0] == '/')
		return true;

	if (path[0] != '/')
		return false;

	for (i = 0; path[i]; i++) {
		if (path[i] == '/' && c == '/')
			return false;

		c = path[i];

		if (is_valid_character(path[i]) || path[i] == '/')
			continue;

		return false;
	}

	if (path[i-1] == '/')
		return false;

	return true;
}

static const char *validate_next_type(const char *sig)
{
	static const char *simple_types = "sogybnqiuxtdh";
	char s = *sig;

	if (s == '\0')
		return NULL;

	if (strchr(simple_types, s) || s == 'v')
		return sig + 1;

	switch (s) {
	case 'a':
		s = *++sig;

		if (s == '{') {
			s = *++sig;

			/* Dictionary keys can only be simple types */
			if (!strchr(simple_types, s))
				return NULL;

			sig = validate_next_type(sig + 1);

			if (!sig)
				return NULL;

			if (*sig != '}')
				return NULL;

			return sig + 1;
		}

		return validate_next_type(sig);

	case '(':
		sig++;

		do
			sig = validate_next_type(sig);
		while (sig && *sig != ')');

		if (!sig)
			return NULL;

		return sig + 1;
	}

	return NULL;
}

bool _dbus_valid_signature(const char *sig)
{
	const char *s = sig;

	do {
		s = validate_next_type(s);

		if (!s)
			return false;
	} while (*s);

	return true;
}

static bool valid_member_name(const char *start, const char *end)
{
	const char *p;

	if ((end - start) < 1)
		return false;

	if (*start >= '0' && *start <= '9')
		return false;

	for (p = start; p < end; p++)
		if (!is_valid_character(*p))
			return false;

	return true;
}

bool _dbus_valid_method(const char *method)
{
	unsigned int i;

	if (!method)
		return false;

	if (method[0] == '\0' || strlen(method) > DBUS_MAX_METHOD_LEN)
		return false;

	if (method[0] >= '0' && method[0] <= '9')
		return false;

	for (i = 0; method[i]; i++)
		if (!is_valid_character(method[i]))
			return false;

	return true;
}

bool _dbus_valid_interface(const char *interface)
{
	const char *sep;

	if (!interface)
		return false;

	if (interface[0] == '\0' || strlen(interface) > DBUS_MAX_INTERFACE_LEN)
		return false;

	sep = strchrnul(interface, '.');
	if (*sep == '\0')
		return false;

	while (true) {
		if (!valid_member_name(interface, sep))
			return false;

		if (*sep == '\0')
			break;

		interface = sep + 1;
		sep = strchrnul(interface, '.');
	}

	return true;
}

const char *_dbus_signature_end(const char *signature)
{
	const char *ptr = signature;
	unsigned int indent = 0;
	char expect;

	switch (*signature) {
	case '(':
		expect = ')';
		break;
	case '{':
		expect = '}';
		break;
	case 'a':
		return _dbus_signature_end(signature + 1);
	default:
		return signature;
	}

	for (ptr = signature; *ptr != '\0'; ptr++) {
		if (*ptr == *signature)
			indent++;
		else if (*ptr == expect)
			if (!--indent)
				return ptr;
	}

	return NULL;
}

bool _dbus1_iter_next_entry_basic(struct dbus1_iter *iter, char type, void *out)
{
	const char *str_val;
	uint8_t uint8_val;
	uint16_t uint16_val;
	uint32_t uint32_val;
	uint64_t uint64_val;
	int16_t int16_val;
	int32_t int32_val;
	int64_t int64_val;
	size_t pos;

	if (iter->pos >= iter->len)
		return false;

	switch (type) {
	case 'o':
	case 's':
		pos = align_len(iter->pos, 4);
		if (pos + 5 > iter->len)
			return false;
		uint32_val = get_u32(iter->data + pos);
		str_val = iter->data + pos + 4;
		*(const void **) out = str_val;
		iter->pos = pos + uint32_val + 5;
		break;
	case 'g':
		pos = align_len(iter->pos, 1);
		if (pos + 2 > iter->len)
			return false;
		uint8_val = get_u8(iter->data + pos);
		str_val = iter->data + pos + 1;
		*(const void **) out = str_val;
		iter->pos = pos + uint8_val + 2;
		break;
	case 'b':
		pos = align_len(iter->pos, 4);
		if (pos + 4 > iter->len)
			return false;
		uint32_val = get_u32(iter->data + pos);
		*(bool *) out = !!uint32_val;
		iter->pos = pos + 4;
		break;
	case 'y':
		pos = align_len(iter->pos, 1);
		if (pos + 1 > iter->len)
			return false;
		uint8_val = get_u8(iter->data + pos);
		*(uint8_t *) out = uint8_val;
		iter->pos = pos + 1;
		break;
	case 'n':
		pos = align_len(iter->pos, 2);
		if (pos + 2 > iter->len)
			return false;
		int16_val = get_s16(iter->data + pos);
		*(int16_t *) out = int16_val;
		iter->pos = pos + 2;
		break;
	case 'q':
		pos = align_len(iter->pos, 2);
		if (pos + 2 > iter->len)
			return false;
		uint16_val = get_u16(iter->data + pos);
		*(uint16_t *) out = uint16_val;
		iter->pos = pos + 2;
		break;
	case 'i':
		pos = align_len(iter->pos, 4);
		if (pos + 4 > iter->len)
			return false;
		int32_val = get_s32(iter->data + pos);
		*(int32_t *) out = int32_val;
		iter->pos = pos + 4;
		break;
	case 'u':
	case 'h':
		pos = align_len(iter->pos, 4);
		if (pos + 4 > iter->len)
			return false;
		uint32_val = get_u32(iter->data + pos);
		*(uint32_t *) out = uint32_val;
		iter->pos = pos + 4;
		break;
	case 'x':
		pos = align_len(iter->pos, 8);
		if (pos + 8 > iter->len)
			return false;
		int64_val = get_s64(iter->data + pos);
		*(int64_t *) out= int64_val;
		iter->pos = pos + 8;
		break;
	case 't':
		pos = align_len(iter->pos, 8);
		if (pos + 8 > iter->len)
			return false;
		uint64_val = get_u64(iter->data + pos);
		*(uint64_t *) out = uint64_val;
		iter->pos = pos + 8;
		break;
	case 'd':
		pos = align_len(iter->pos, 8);
		if (pos + 8 > iter->len)
			return false;
		uint64_val = get_u64(iter->data + pos);
		*(double *) out = (double) uint64_val;
		iter->pos = pos + 8;
		break;
	default:
		return false;
	}

	if (iter->container_type != DBUS_CONTAINER_TYPE_ARRAY)
		iter->sig_pos += 1;

	return true;
}
