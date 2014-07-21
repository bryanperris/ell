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

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>

#include "dbus.h"
#include "private.h"
#include "dbus-private.h"
#include "string.h"
#include "queue.h"

#define DBUS_MAX_INTERFACE_LEN 255
#define DBUS_MAX_METHOD_LEN 255

static const char *simple_types = "sogybnqiuxtdh";

static int get_alignment(const char type)
{
	switch (type) {
	case 'b':
		return 4;
	case 'y':
		return 1;
	case 'n':
	case 'q':
		return 2;
	case 'u':
	case 'i':
		return 4;
	case 'x':
	case 't':
	case 'd':
		return 8;
	case 's':
	case 'o':
		return 4;
	case 'g':
		return 1;
	case 'a':
		return 4;
	case '(':
	case '{':
		return 8;
	case 'v':
		return 1;
	case 'h':
		return 4;
	default:
		return 0;
	}
}

static int get_basic_size(const char type)
{
	switch (type) {
	case 'b':
		return 4;
	case 'y':
		return 1;
	case 'n':
	case 'q':
		return 2;
	case 'i':
	case 'u':
		return 4;
	case 'x':
	case 't':
		return 8;
	case 'd':
		return 8;
	case 'h':
		return 4;
	default:
		return 0;
	}
}

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

static inline void dbus1_iter_init_internal(struct l_dbus_message_iter *iter,
						struct l_dbus_message *message,
						enum dbus_container_type type,
						const char *sig_start,
						const char *sig_end,
						const void *data, size_t len,
						size_t pos)
{
	size_t sig_len;

	iter->message = message;

	if (sig_end)
		sig_len = sig_end - sig_start;
	else
		sig_len = strlen(sig_start);

	iter->sig_start = sig_start;
	iter->sig_len = sig_len;
	iter->sig_pos = 0;
	iter->data = data;
	iter->len = pos + len;
	iter->pos = pos;
	iter->container_type = type;
}

void _dbus1_iter_init(struct l_dbus_message_iter *iter,
			struct l_dbus_message *message,
			const char *sig_start, const char *sig_end,
			const void *data, size_t len)
{
	dbus1_iter_init_internal(iter, message, DBUS_CONTAINER_TYPE_STRUCT,
					sig_start, sig_end, data, len, 0);
}

static const char *calc_len_next_item(const char *signature, const void *data,
					size_t data_pos, size_t data_len,
					size_t *out_len)
{
	unsigned int alignment;
	size_t pos;
	size_t len;
	const char *sig_end;
	const char *var_sig;

	alignment = get_alignment(*signature);
	if (alignment == 0)
		return NULL;

	pos = align_len(data_pos, alignment);
	if (pos > data_len)
		return NULL;

	switch (*signature) {
	case 'o':
	case 's':
		if (pos + 5 > data_len)
			return NULL;

		pos += get_u32(data + pos) + 5;
		break;
	case 'g':
		if (pos + 2 > data_len)
			return NULL;

		pos += get_u8(data + pos) + 2;
		break;
	case 'y':
		pos += 1;
		break;
	case 'n':
	case 'q':
		pos += 2;
		break;
	case 'b':
	case 'i':
	case 'u':
	case 'h':
		pos += 4;
		break;
	case 'x':
	case 't':
	case 'd':
		pos += 8;
		break;
	case 'a':
		if (pos + 4 > data_len)
			return NULL;

		len = get_u32(data + pos);
		pos += 4;

		alignment = get_alignment(signature[1]);
		pos = align_len(pos, alignment);
		pos += len;

		sig_end = _dbus_signature_end(signature) + 1;
		goto done;
	case '(':
		sig_end = signature + 1;

		while (*sig_end != ')') {
			sig_end = calc_len_next_item(sig_end, data, pos,
							data_len, &len);

			if (!sig_end)
				return NULL;

			pos += len;
		}

		sig_end += 1;
		goto done;
	case '{':
		sig_end = calc_len_next_item(signature + 1, data, pos,
						data_len, &len);

		if (!sig_end)
			return NULL;

		pos += len;

		sig_end = calc_len_next_item(sig_end, data, pos,
						data_len, &len);

		if (!sig_end)
			return NULL;

		pos += len;
		sig_end += 1;
		goto done;
	case 'v':
		if (!calc_len_next_item("g", data, pos, data_len, &len))
			return NULL;

		var_sig = data + pos + 1;
		pos += len;

		if (!calc_len_next_item(var_sig, data, pos, data_len, &len))
			return NULL;

		pos += len;
		break;
	default:
		return NULL;
	}

	sig_end = signature + 1;

done:
	if (pos > data_len)
		return NULL;

	*out_len = pos - data_pos;
	return sig_end;
}

bool _dbus1_iter_next_entry_basic(struct l_dbus_message_iter *iter,
					char type, void *out)
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

	pos = align_len(iter->pos, get_alignment(type));

	switch (type) {
	case 'o':
	case 's':
		if (pos + 5 > iter->len)
			return false;
		uint32_val = get_u32(iter->data + pos);
		str_val = iter->data + pos + 4;
		*(const void **) out = str_val;
		iter->pos = pos + uint32_val + 5;
		break;
	case 'g':
		if (pos + 2 > iter->len)
			return false;
		uint8_val = get_u8(iter->data + pos);
		str_val = iter->data + pos + 1;
		*(const void **) out = str_val;
		iter->pos = pos + uint8_val + 2;
		break;
	case 'b':
		if (pos + 4 > iter->len)
			return false;
		uint32_val = get_u32(iter->data + pos);
		*(bool *) out = !!uint32_val;
		iter->pos = pos + 4;
		break;
	case 'y':
		if (pos + 1 > iter->len)
			return false;
		uint8_val = get_u8(iter->data + pos);
		*(uint8_t *) out = uint8_val;
		iter->pos = pos + 1;
		break;
	case 'n':
		if (pos + 2 > iter->len)
			return false;
		int16_val = get_s16(iter->data + pos);
		*(int16_t *) out = int16_val;
		iter->pos = pos + 2;
		break;
	case 'q':
		if (pos + 2 > iter->len)
			return false;
		uint16_val = get_u16(iter->data + pos);
		*(uint16_t *) out = uint16_val;
		iter->pos = pos + 2;
		break;
	case 'i':
		if (pos + 4 > iter->len)
			return false;
		int32_val = get_s32(iter->data + pos);
		*(int32_t *) out = int32_val;
		iter->pos = pos + 4;
		break;
	case 'u':
	case 'h':
		if (pos + 4 > iter->len)
			return false;
		uint32_val = get_u32(iter->data + pos);
		*(uint32_t *) out = uint32_val;
		iter->pos = pos + 4;
		break;
	case 'x':
		if (pos + 8 > iter->len)
			return false;
		int64_val = get_s64(iter->data + pos);
		*(int64_t *) out= int64_val;
		iter->pos = pos + 8;
		break;
	case 't':
		if (pos + 8 > iter->len)
			return false;
		uint64_val = get_u64(iter->data + pos);
		*(uint64_t *) out = uint64_val;
		iter->pos = pos + 8;
		break;
	case 'd':
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

bool _dbus1_iter_enter_struct(struct l_dbus_message_iter *iter,
					struct l_dbus_message_iter *structure)
{
	size_t len;
	size_t pos;
	const char *sig_start;
	const char *sig_end;
	bool is_dict = iter->sig_start[iter->sig_pos] == '{';
	bool is_struct = iter->sig_start[iter->sig_pos] == '(';

	if (!is_dict && !is_struct)
		return false;

	pos = align_len(iter->pos, 8);
	if (pos >= iter->len)
		return false;

	sig_start = iter->sig_start + iter->sig_pos + 1;
	sig_end = _dbus_signature_end(iter->sig_start + iter->sig_pos);

	if (!calc_len_next_item(iter->sig_start + iter->sig_pos,
				iter->data, pos, iter->len, &len))
		return false;

	dbus1_iter_init_internal(structure, iter->message,
					DBUS_CONTAINER_TYPE_STRUCT,
					sig_start, sig_end, iter->data,
					len, pos);

	if (iter->container_type != DBUS_CONTAINER_TYPE_ARRAY)
		iter->sig_pos += sig_end - sig_start + 2;

	iter->pos = pos + len;

	return true;
}

bool _dbus1_iter_enter_variant(struct l_dbus_message_iter *iter,
					struct l_dbus_message_iter *variant)
{
	size_t pos;
	uint8_t sig_len;
	size_t len;
	const char *sig_start;

	if (iter->sig_start[iter->sig_pos] != 'v')
		return false;

	pos = align_len(iter->pos, 1);
	if (pos + 2 > iter->len)
		return false;

	sig_len = get_u8(iter->data + pos);
	sig_start = iter->data + pos + 1;

	if (!calc_len_next_item(sig_start, iter->data, pos + sig_len + 2,
					iter->len, &len))
		return false;

	dbus1_iter_init_internal(variant, iter->message,
					DBUS_CONTAINER_TYPE_VARIANT,
					sig_start, NULL, iter->data,
					len, pos + sig_len + 2);

	if (iter->container_type != DBUS_CONTAINER_TYPE_ARRAY)
		iter->sig_pos += 1;

	iter->pos = pos + sig_len + 2 + len;

	return true;
}

bool _dbus1_iter_enter_array(struct l_dbus_message_iter *iter,
					struct l_dbus_message_iter *array)
{
	size_t pos;
	size_t len;
	const char *sig_start;
	const char *sig_end;

	if (iter->sig_start[iter->sig_pos] != 'a')
		return false;

	sig_start = iter->sig_start + iter->sig_pos + 1;
	sig_end = _dbus_signature_end(sig_start) + 1;

	pos = align_len(iter->pos, 4);
	if (pos + 4 > iter->len)
		return false;

	len = get_u32(iter->data + pos);
	pos += 4;

	pos = align_len(pos, get_alignment(*sig_start));
	dbus1_iter_init_internal(array, iter->message,
					DBUS_CONTAINER_TYPE_ARRAY,
					sig_start, sig_end,
					iter->data, len, pos);

	if (iter->container_type != DBUS_CONTAINER_TYPE_ARRAY)
		iter->sig_pos += sig_end - sig_start + 1;

	iter->pos = pos + len;

	return true;
}

struct dbus1_builder {
	struct l_string *signature;
	void *body;
	size_t body_size;
	struct l_queue *containers;
};

struct container {
	size_t start;
	enum dbus_container_type type;
	char signature[256];
	uint8_t sigindex;
};

static struct container *container_new(enum dbus_container_type type,
					const char *signature, size_t start)
{
	struct container *ret;

	ret = l_new(struct container, 1);

	ret->type = type;
	strcpy(ret->signature, signature);
	ret->start = start;

	return ret;
}

static void container_free(struct container *container)
{
	l_free(container);
}

static inline size_t grow_body(struct dbus1_builder *builder,
					size_t len, unsigned int alignment)
{
	size_t size = align_len(builder->body_size, alignment);

	if (size + len > builder->body_size) {
		builder->body = l_realloc(builder->body, size + len);

		if (size - builder->body_size > 0)
			memset(builder->body + builder->body_size, 0,
						size - builder->body_size);

		builder->body_size = size + len;
	}

	return size;
}

struct dbus1_builder *_dbus1_builder_new(void)
{
	struct dbus1_builder *builder;
	struct container *root;

	builder = l_new(struct dbus1_builder, 1);
	builder->signature = l_string_new(63);

	builder->containers = l_queue_new();
	root = container_new(DBUS_CONTAINER_TYPE_STRUCT, "", 0);
	l_queue_push_head(builder->containers, root);

	return builder;
}

void _dbus1_builder_free(struct dbus1_builder *builder)
{
	if (unlikely(!builder))
		return;

	l_string_free(builder->signature, true);
	l_queue_destroy(builder->containers,
				(l_queue_destroy_func_t) container_free);
	l_free(builder->body);

	l_free(builder);
}

bool _dbus1_builder_append_basic(struct dbus1_builder *builder,
					char type, const void *value)
{
	struct container *container = l_queue_peek_head(builder->containers);
	size_t start;
	unsigned int alignment;
	size_t len;
	size_t offset;

	if (unlikely(!builder))
		return false;

	if (unlikely(!strchr(simple_types, type)))
		return false;

	alignment = get_alignment(type);
	if (!alignment)
		return false;

	if (l_queue_length(builder->containers) == 1)
		l_string_append_c(builder->signature, type);
	else if (container->signature[container->sigindex] != type)
		return false;

	len = get_basic_size(type);

	if (len) {
		uint32_t b;

		start = grow_body(builder, len, alignment);

		if (type == 'b') {
			b = *(bool *)value;
			memcpy(builder->body + start, &b, len);
		} else
			memcpy(builder->body + start, value, len);

		if (container->type != DBUS_CONTAINER_TYPE_ARRAY)
			container->sigindex += 1;

		return true;
	}

	len = strlen(value);

	if (type == 'g') {
		start = grow_body(builder, len + 2, 1);
		put_u8(builder->body + start, len);
		strcpy(builder->body + start + 1, value);
	} else {
		start = grow_body(builder, len + 5, 4);
		put_u32(builder->body + start, len);
		strcpy(builder->body + start + 4, value);
	}

	if (container->type != DBUS_CONTAINER_TYPE_ARRAY)
		container->sigindex += 1;

	return true;
}

char *_dbus1_builder_finish(struct dbus1_builder *builder,
				void **body, size_t *body_size)
{
	char *signature;
	struct container *root;

	if (unlikely(!builder))
		return NULL;

	if (unlikely(l_queue_length(builder->containers) != 1))
		return NULL;

	root = l_queue_peek_head(builder->containers);

	signature = l_string_free(builder->signature, false);
	builder->signature = NULL;

	*body = builder->body;
	*body_size = builder->body_size;

	return signature;
}
