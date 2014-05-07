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
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <endian.h>

#include "private.h"
#include "util.h"
#include "log.h"
#include "dbus-private.h"
#include "gvariant-private.h"

static const char *simple_types = "sogybnqiuxtdh";
static const char *variable_types = "sogav";
static const char *fixed_types = "bynqhiuxtd";

/* The alignment of a container type is equal to the largest alignment of
 * any potential child of that container. This means that, even if an array
 * of 32-bit integers is empty, it still must be aligned to the nearest
 * multiple of 4 bytes. It also means that the variant type (described below)
 * has an alignment of 8 (since it could potentially contain a value of any
 * other type and the maximum alignment is 8).
 */
static int get_basic_alignment(const char type)
{
	switch (type) {
	case 'b':
		return 1;
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
	case 'd':
		return 8;
	case 's':
	case 'g':
	case 'o':
		return 1;
	case 'h':
		return 4;
	case 'v':
		return 8;
	default:
		return 0;
	}
}

static int get_basic_fixed_size(const char type)
{
	switch (type) {
	case 'b':
		return 1;
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
	case 'd':
		return 8;
	case 'h':
		return 4;
	default:
		return 0;
	}
}

static const char *validate_next_type(const char *sig, int *out_alignment)
{
	char s = *sig;
	int alignment;

	if (s == '\0')
		return NULL;

	if (strchr(simple_types, s) || s == 'v') {
		*out_alignment = get_basic_alignment(s);
		return sig + 1;
	}

	switch (s) {
	case 'a':
		return validate_next_type(++sig, out_alignment);

	case '{':
		s = *++sig;

		/* Dictionary keys can only be simple types */
		if (!strchr(simple_types, s))
			return NULL;

		alignment = get_basic_alignment(s);

		sig = validate_next_type(sig + 1, out_alignment);

		if (!sig)
			return NULL;

		if (*sig != '}')
			return NULL;

		if (alignment > *out_alignment)
			*out_alignment = alignment;

		return sig + 1;

	case '(':
	{
		int max_alignment = 1, alignment;

		sig++;

		while (sig && *sig != ')') {
			sig = validate_next_type(sig, &alignment);

			if (alignment > max_alignment)
				max_alignment = alignment;
		}

		if (!sig)
			return NULL;

		if (*sig != ')')
			return NULL;

		*out_alignment = max_alignment;

		return sig + 1;
	}
	}

	return NULL;
}

bool _gvariant_valid_signature(const char *sig)
{
	const char *s = sig;
	int a;

	do {
		s = validate_next_type(s, &a);

		if (!s)
			return false;
	} while (*s);

	return true;
}

int _gvariant_num_children(const char *sig)
{
	const char *s = sig;
	int a;
	int num_children = 0;

	do {
		s = validate_next_type(s, &a);

		if (!s)
			return -1;

		num_children += 1;
	} while (*s);

	return num_children;
}

int _gvariant_get_alignment(const char *sig)
{
	int max_alignment = 1, alignment;
	const char *s = sig;

	/* 8 is the largest alignment possible, so quit if we reach it */
	while (*s && max_alignment != 8) {
		s = validate_next_type(s, &alignment);
		if (!s)
			return 0;

		if (alignment > max_alignment)
			max_alignment = alignment;
	}

	return max_alignment;
}

bool _gvariant_is_fixed_size(const char *sig)
{
	while (*sig != 0) {
		if (strchr(variable_types, sig[0]))
			return false;

		sig += 1;
	}

	return true;
}

int _gvariant_get_fixed_size(const char *sig)
{
	const char *s = sig;
	const char *p;
	int size = 0;
	int alignment;
	int max_alignment = 1;
	int r;

	while (*s) {
		if (strchr(variable_types, *s))
			return 0;

		if (strchr(fixed_types, *s)) {
			alignment = get_basic_alignment(*s);

			if (alignment > max_alignment)
				max_alignment = alignment;

			size = align_len(size, alignment);
			size += get_basic_fixed_size(*s);
			s++;
			continue;
		}

		if (*s == '}' || *s == ')')
			break;

		p = validate_next_type(s, &alignment);

		if (!p)
			return 0;

		if (alignment > max_alignment)
			max_alignment = alignment;

		size = align_len(size, alignment);

		/* Handle special case of unit type */
		if (s[0] == '(' && s[1] == ')')
			r = 1;
		else
			r = _gvariant_get_fixed_size(s + 1);

		if (r == 0)
			return 0;

		size += r;
		s = p;
	}

	size = align_len(size, max_alignment);

	return size;
}

static inline size_t offset_length(size_t size)
{
	if (size <= 0xff)
		return 1;
	if (size <= 0xffff)
		return 2;
	if (size <= 0xffffffff)
		return 4;
	else
		return 8;
}

static inline size_t read_word_le(const void *p, size_t sz) {
	union {
		uint16_t u16;
		uint32_t u32;
		uint64_t u64;
	} x;

	if (sz == 1)
		return *(uint8_t*) p;

	memcpy(&x, p, sz);

	if (sz == 2)
		return le16toh(x.u16);
	else if (sz == 4)
		return le32toh(x.u32);
	else
		return le64toh(x.u64);
}

bool _gvariant_iter_init(struct gvariant_iter *iter, const char *sig_start,
				const char *sig_end, const void *data,
				size_t len)
{
	const char *p;
	int i;
	char subsig[256];
	unsigned int num_variable = 0;
	unsigned int offset_len = offset_length(len);
	size_t last_offset;

	if (sig_end) {
		size_t len = sig_end - sig_start;
		memcpy(subsig, sig_start, len);
		subsig[len] = '\0';
	} else
		strcpy(subsig, sig_start);

	l_info("IterInit: '%s', '%s':'%s'", subsig, sig_start, sig_end);

	iter->sig_start = sig_start;
	iter->sig_end = sig_end;
	iter->data = data;
	iter->len = len;
	iter->cur_child = 0;

	iter->n_children = _gvariant_num_children(subsig);
	iter->children = l_new(struct gvariant_type_info, iter->n_children);

	l_info("Children: %d", iter->n_children);

	for (p = sig_start, i = 0; i < iter->n_children; i++) {
		int alignment;
		size_t size;
		size_t len;

		iter->children[i].sig_start = p - sig_start;
		p = validate_next_type(p, &alignment);
		iter->children[i].sig_end = p - sig_start;

		len = iter->children[i].sig_end - iter->children[i].sig_start;
		memcpy(subsig, sig_start + iter->children[i].sig_start, len);
		subsig[len] = '\0';

		iter->children[i].alignment = alignment;
		iter->children[i].fixed_size = _gvariant_is_fixed_size(subsig);

		if (iter->children[i].fixed_size) {
			size = _gvariant_get_fixed_size(subsig);
			iter->children[i].end = size;
		} else if (i + 1 < iter->n_children)
			num_variable += 1;
	}

	if (len < num_variable * offset_len)
		return false;

	last_offset = len - num_variable * offset_len;

	l_info("Variable Structs: %d, Offset Length: %d",
		num_variable, offset_len);

	for (i = 0; i < iter->n_children; i++) {
		size_t o;

		if (iter->children[i].fixed_size) {
			if (i == 0)
				continue;

			o = align_len(iter->children[i-1].end,
					iter->children[i].alignment);
			iter->children[i].end += o;

			if (iter->children[i].end > len)
				goto fail;

			continue;
		}

		if (num_variable == 0) {
			iter->children[i].end = last_offset;
			continue;
		}

		iter->children[i].end =
			read_word_le(data + len - offset_len * num_variable,
					offset_len);
		num_variable -= 1;

		if (iter->children[i].end > len)
			goto fail;
	}

	for (i = 0; i < iter->n_children; i++) {
		len = iter->children[i].sig_end - iter->children[i].sig_start;
		memcpy(subsig, sig_start + iter->children[i].sig_start, len);
		subsig[len] = '\0';

		l_info("\tChild%d: Signature:'%s' Fixed:%s "
			"Alignment:%u, End Offset: %zu",
				i, subsig,
				iter->children[i].fixed_size ? "True" : "False",
				iter->children[i].alignment,
				iter->children[i].end);
	}

	iter->container_type = DBUS_CONTAINER_TYPE_STRUCT;

	return true;

fail:
	_gvariant_iter_free(iter);
	return false;
}

void _gvariant_iter_free(struct gvariant_iter *iter)
{
	l_free(iter->children);
}

static const void *vararray_find_nth(struct gvariant_iter *iter,
							size_t *out_item_size)
{
	const void *start = iter->data;
	unsigned int offset_len = offset_length(iter->len);
	/*
	 * offset is effectively the end of the last element
	 * and start of the offset array
	 */
	size_t offset = read_word_le(start + iter->len - offset_len,
					offset_len);
	size_t n_items = (iter->len - offset) / offset_len;
	size_t item_end_offset;

	if (iter->cur_child >= n_items)
		return NULL;

	if (n_items * offset_len > iter->len)
		return NULL;

	item_end_offset = offset + iter->cur_child * offset_len;
	item_end_offset = read_word_le(start + item_end_offset, offset_len);

	if (iter->cur_child > 0) {
		offset += (iter->cur_child - 1) * offset_len;
		offset = read_word_le(start + offset, offset_len);
	} else
		offset = 0;

	offset = align_len(offset, iter->children[0].alignment);
	start += offset;

	*out_item_size = iter->data + item_end_offset - start;

	return start;
}

static const void *next_item(struct gvariant_iter *iter, size_t *out_item_size)
{
	const void *start = iter->data;
	size_t c = iter->cur_child;

	switch (iter->container_type) {
	case DBUS_CONTAINER_TYPE_DICT_ENTRY:
	case DBUS_CONTAINER_TYPE_STRUCT:
	case DBUS_CONTAINER_TYPE_VARIANT:
		if (iter->cur_child == 0) {
			*out_item_size = iter->children[0].end;
			return start;
		}

		start += align_len(iter->children[c-1].end,
					iter->children[c].alignment);
		*out_item_size = iter->data + iter->children[c].end - start;
		return start;
	/*
	 * For arrays, we need to figure out the offset.  There are two cases:
	 * - Fixed arrays, in which case we simply use the size of the item
	 * - Variable arrays, in which case we need to look up the end offset
	 */
	case DBUS_CONTAINER_TYPE_ARRAY:
		if (iter->children[0].fixed_size) {
			start += iter->cur_child * iter->children[0].end;
			*out_item_size = iter->children[0].end;
			return start;
		}

		return vararray_find_nth(iter, out_item_size);
	}
}

#define get_u8(ptr)		(*(uint8_t *) (ptr))
#define get_u16(ptr)		(*(uint16_t *) (ptr))
#define get_u32(ptr)		(*(uint32_t *) (ptr))
#define get_u64(ptr)		(*(uint64_t *) (ptr))
#define get_s16(ptr)		(*(int16_t *) (ptr))
#define get_s32(ptr)		(*(int32_t *) (ptr))
#define get_s64(ptr)		(*(int64_t *) (ptr))

bool _gvariant_iter_next_entry_basic(struct gvariant_iter *iter, char type,
					void *out)
{
	size_t c;
	size_t item_size = 0;
	const void *start;
	uint8_t uint8_val;
	uint16_t uint16_val;
	uint32_t uint32_val;
	uint64_t uint64_val;
	int16_t int16_val;
	int32_t int32_val;
	int64_t int64_val;

	if (iter->container_type == DBUS_CONTAINER_TYPE_ARRAY)
		c = 0;
	else
		c = iter->cur_child;

	if (c >= iter->n_children)
		return false;

	if (iter->children[c].sig_end - iter->children[c].sig_start > 1)
		return false;

	if (iter->sig_start[iter->children[c].sig_start] != type)
		return false;

	start = next_item(iter, &item_size);
	if (!start)
		return false;

	if (start >= iter->data + iter->len)
		return false;

	switch (type) {
	case 'o':
	case 's':
	case 'g':
	{
		const void *end = memchr(start, 0, item_size);

		if (!end)
			return false;

		*(const char**) out = start;
		break;
	}
	case 'b':
		uint8_val = get_u8(start);
		*(bool *) out = !!uint8_val;
		break;
	case 'y':
		uint8_val = get_u8(start);
		*(uint8_t *) out = uint8_val;
		break;
	case 'n':
		int16_val = get_s16(start);
		*(int16_t *) out = int16_val;
		break;
	case 'q':
		uint16_val = get_u16(start);
		*(uint16_t *) out = uint16_val;
		break;
	case 'i':
		int32_val = get_s32(start);
		*(int32_t *) out = int32_val;
		break;
	case 'h':
	case 'u':
		uint32_val = get_u32(start);
		*(uint32_t *) out = uint32_val;
		break;
	case 'x':
		int64_val = get_s64(start);
		*(int64_t *) out = int64_val;
		break;
	case 't':
		uint64_val = get_u64(start);
		*(uint64_t *) out = uint64_val;
		break;
	case 'd':
		uint64_val = get_u64(start);
		*(uint64_t *) out = uint64_val;
		break;
	}

	iter->cur_child += 1;
	return true;
}

bool _gvariant_iter_enter_struct(struct gvariant_iter *iter,
					struct gvariant_iter *structure)
{
	size_t c;
	const void *start;
	bool ret;
	size_t item_size;

	if (iter->container_type == DBUS_CONTAINER_TYPE_ARRAY)
		c = 0;
	else
		c = iter->cur_child;

	if (c >= iter->n_children)
		return false;

	if (iter->sig_start[iter->children[c].sig_start] != '(' &&
			iter->sig_start[iter->children[c].sig_start] != '{')
		return false;

	if (iter->children[c].sig_end - iter->children[c].sig_start <= 2)
		return false;

	start = next_item(iter, &item_size);
	if (!start)
		return false;

	if (start >= iter->data + iter->len)
		return false;

	ret = _gvariant_iter_init(structure,
			iter->sig_start + iter->children[c].sig_start + 1,
			iter->sig_start + iter->children[c].sig_end - 1,
			start, item_size);

	if (ret)
		iter->cur_child += 1;

	if (iter->sig_start[iter->children[c].sig_start] == '{')
		structure->container_type = DBUS_CONTAINER_TYPE_DICT_ENTRY;

	return ret;
}

bool _gvariant_iter_enter_variant(struct gvariant_iter *iter,
					struct gvariant_iter *variant)
{
	size_t c = iter->cur_child;
	size_t item_size;
	const void *start, *end, *nul;
	bool ret;
	char signature[255];

	if (iter->container_type == DBUS_CONTAINER_TYPE_ARRAY)
		c = 0;
	else
		c = iter->cur_child;

	if (c >= iter->n_children)
		return false;

	if (iter->children[c].sig_end - iter->children[c].sig_start != 1)
		return false;

	if (iter->sig_start[iter->children[c].sig_start] != 'v')
		return false;

	start = next_item(iter, &item_size);
	if (!start)
		return false;

	if (start >= iter->data + iter->len)
		return false;

	/* Find the signature */
	end = start + item_size;
	nul = memrchr(start, 0, end - start);

	if (!nul)
		return false;

	if (end - nul - 1 > 255)
		return false;

	memcpy(signature, nul + 1, end - nul - 1);
	signature[end - nul - 1] = '\0';

	if (!_gvariant_valid_signature(signature))
		return false;

	if (_gvariant_num_children(signature) != 1)
		return false;

	ret = _gvariant_iter_init(variant, nul + 1, end,
					start, nul - start);

	variant->container_type = DBUS_CONTAINER_TYPE_VARIANT;

	if (ret)
		iter->cur_child += 1;

	return ret;
}

bool _gvariant_iter_enter_array(struct gvariant_iter *iter,
					struct gvariant_iter *array)
{
	size_t c = iter->cur_child;
	size_t item_size;
	const void *start;
	unsigned char siglen;
	bool ret;
	char signature[256];

	if (iter->container_type == DBUS_CONTAINER_TYPE_ARRAY)
		c = 0;
	else
		c = iter->cur_child;

	if (c >= iter->n_children)
		return false;

	if (iter->sig_start[iter->children[c].sig_start] != 'a')
		return false;

	siglen = iter->children[c].sig_end - iter->children[c].sig_start - 1;
	memcpy(signature, iter->sig_start + iter->children[c].sig_start + 1,
		siglen);
	signature[siglen] = '\0';

	if (_gvariant_num_children(signature) != 1)
		return false;

	start = next_item(iter, &item_size);
	if (start >= iter->data + iter->len)
		return false;

	ret = _gvariant_iter_init(array,
			iter->sig_start + iter->children[c].sig_start + 1,
			iter->sig_start + iter->children[c].sig_end,
			start, item_size);

	array->container_type = DBUS_CONTAINER_TYPE_ARRAY;

	if (ret)
		iter->cur_child += 1;

	return ret;
}
