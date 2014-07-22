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
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>

#include "util.h"
#include "private.h"
#include "dbus.h"
#include "dbus-private.h"
#include "gvariant-private.h"

#define DBUS_MESSAGE_LITTLE_ENDIAN	('l')
#define DBUS_MESSAGE_BIG_ENDIAN		('B')

#define DBUS_MESSAGE_PROTOCOL_VERSION	1

#define DBUS_MESSAGE_FLAG_NO_REPLY_EXPECTED	0x01
#define DBUS_MESSAGE_FLAG_NO_AUTO_START		0x02

#define DBUS_MESSAGE_FIELD_PATH		1
#define DBUS_MESSAGE_FIELD_INTERFACE	2
#define DBUS_MESSAGE_FIELD_MEMBER	3
#define DBUS_MESSAGE_FIELD_ERROR_NAME	4
#define DBUS_MESSAGE_FIELD_REPLY_SERIAL	5
#define DBUS_MESSAGE_FIELD_DESTINATION	6
#define DBUS_MESSAGE_FIELD_SENDER	7
#define DBUS_MESSAGE_FIELD_SIGNATURE	8
#define DBUS_MESSAGE_FIELD_UNIX_FDS	9

struct l_dbus_message {
	int refcount;
	void *header;
	size_t header_size;
	const char *signature;
	void *body;
	size_t body_size;
	char *path;
	char *interface;
	char *member;
	char *destination;
	char *sender;
	int fds[16];
	uint32_t num_fds;
};

static inline bool _dbus_message_is_gvariant(struct l_dbus_message *msg)
{
	struct dbus_header *hdr = msg->header;

	return hdr->version == 2;
}

void *_dbus_message_get_header(struct l_dbus_message *msg, size_t *out_size)
{
	if (out_size)
		*out_size = msg->header_size;

	return msg->header;
}

void *_dbus_message_get_body(struct l_dbus_message *msg, size_t *out_size)
{
	if (out_size)
		*out_size = msg->body_size;

	return msg->body;
}

void _dbus_message_set_serial(struct l_dbus_message *msg, uint32_t serial)
{
	struct dbus_header *hdr = msg->header;

	hdr->serial = serial;
}

static unsigned int encode_header(unsigned char field, char type,
			const char *value, uint32_t len, void *data)
{
	unsigned char *ptr = data;

	ptr[0] = field;
	ptr[1] = 0x01;
	ptr[2] = (unsigned char) type;
	ptr[3] = 0x00;
	ptr[4] = (unsigned char) len;

	if (type == 's' || type == 'o') {
		ptr[5] = 0x00;
		ptr[6] = 0x00;
		ptr[7] = 0x00;

		strcpy(data + 8, value);

		return 4 + 4 + len + 1;
	} else {
		strcpy(data + 5, value);

		return 4 + 1 + len + 1;
	}
}

LIB_EXPORT struct l_dbus_message *l_dbus_message_new_method_call(const char *destination,
                const char *path, const char *interface, const char *method)
{
	struct l_dbus_message *message;
	struct dbus_header *hdr;
	unsigned int len;
	uint32_t dlen, plen, ilen, mlen;
	uint32_t size;

	message = l_new(struct l_dbus_message, 1);

	message->refcount = 1;

	dlen = strlen(destination);
	plen = strlen(path);
	ilen = strlen(interface);
	mlen = strlen(method);

	size = DBUS_HEADER_SIZE +
			align_len(dlen + 9, 8) + align_len(plen + 9, 8) +
			align_len(ilen + 9, 8) + align_len(mlen + 9, 8);

	message->header = l_malloc(size);

	memset(message->header, 0, size);

	hdr = message->header;

	hdr->endian = DBUS_MESSAGE_LITTLE_ENDIAN;
	hdr->message_type = DBUS_MESSAGE_TYPE_METHOD_CALL;
	hdr->flags = DBUS_MESSAGE_FLAG_NO_AUTO_START;
	hdr->version = DBUS_MESSAGE_PROTOCOL_VERSION;
	hdr->body_length = 0;
	hdr->serial = 0x00;

	len = DBUS_HEADER_SIZE;

	len += encode_header(6, 's', destination, dlen, message->header + len);
	len = align_len(len, 8);
	len += encode_header(1, 'o', path, plen, message->header + len);
	len = align_len(len, 8);
	len += encode_header(2, 's', interface, ilen, message->header + len);
	len = align_len(len, 8);
	len += encode_header(3, 's', method, mlen, message->header + len);

	message->header_size = size;

	hdr->field_length = len - DBUS_HEADER_SIZE;

	return message;
}

LIB_EXPORT struct l_dbus_message *l_dbus_message_ref(struct l_dbus_message *message)
{
	if (unlikely(!message))
		return NULL;

	__sync_fetch_and_add(&message->refcount, 1);

	return message;
}

LIB_EXPORT void l_dbus_message_unref(struct l_dbus_message *message)
{
	unsigned int i;

	if (unlikely(!message))
		return;

	if (__sync_sub_and_fetch(&message->refcount, 1))
		return;

	for (i = 0; i < message->num_fds; i++)
		close(message->fds[i]);

	l_free(message->header);
	l_free(message->body);
	l_free(message);
}

static bool message_iter_next_entry_valist(struct l_dbus_message_iter *orig,
						va_list args)
{
	static const char *simple_types = "sogybnqiuxtd";
	struct l_dbus_message_iter *iter = orig;
	const char *signature = orig->sig_start + orig->sig_pos;
	const char *end;
	struct l_dbus_message_iter *sub_iter;
	struct l_dbus_message_iter stack[32];
	unsigned int indent = 0;
	uint32_t uint32_val;
	int fd;
	void *arg;
	bool (*get_basic)(struct l_dbus_message_iter *, char ,void *);
	bool (*enter_struct)(struct l_dbus_message_iter *,
				struct l_dbus_message_iter *);
	bool (*enter_array)(struct l_dbus_message_iter *,
				struct l_dbus_message_iter *);
	bool (*enter_variant)(struct l_dbus_message_iter *,
				struct l_dbus_message_iter *);

	if (_dbus_message_is_gvariant(orig->message)) {
		get_basic = _gvariant_iter_next_entry_basic;
		enter_struct = _gvariant_iter_enter_struct;
		enter_array = _gvariant_iter_enter_array;
		enter_variant = _gvariant_iter_enter_variant;
	} else {
		get_basic = _dbus1_iter_next_entry_basic;
		enter_struct = _dbus1_iter_enter_struct;
		enter_array = _dbus1_iter_enter_array;
		enter_variant = _dbus1_iter_enter_variant;
	}

	while (signature < orig->sig_start + orig->sig_len) {
		if (strchr(simple_types, *signature)) {
			arg = va_arg(args, void *);
			if (!get_basic(iter, *signature, arg))
				return false;

			signature += 1;
			continue;
		}

		switch (*signature) {
		case 'h':
			if (!get_basic(iter, 'h', &uint32_val))
				return false;

			if (uint32_val < iter->message->num_fds)
				fd = fcntl(iter->message->fds[uint32_val],
						F_DUPFD_CLOEXEC, 3);
			else
				fd = -1;

			*va_arg(args, int *) = fd;
			signature += 1;
			break;
		case '(':
		case '{':
			signature += 1;
			indent += 1;

			if (!enter_struct(iter, &stack[indent - 1]))
				return false;

			iter = &stack[indent - 1];

			break;
		case ')':
		case '}':
			signature += 1;
			indent -= 1;

			if (indent == 0)
				iter = orig;
			else
				iter = &stack[indent - 1];
			break;
		case 'a':
			sub_iter = va_arg(args, void *);

			if (!enter_array(iter, sub_iter))
				return false;

			end = _dbus_signature_end(signature + 1);
			signature = end + 1;
			break;
		case 'v':
			sub_iter = va_arg(args, void *);

			if (!enter_variant(iter, sub_iter))
				return false;

			signature += 1;
			break;
		default:
			return false;
		}
	}

	return true;
}

static inline bool message_iter_next_entry(struct l_dbus_message_iter *iter,
						...)
{
	va_list args;
	bool result;

        va_start(args, iter);
	result = message_iter_next_entry_valist(iter, args);
	va_end(args);

	return result;
}

static bool get_header_field_from_iter_valist(struct l_dbus_message *message,
						uint8_t type, va_list args)
{
	struct l_dbus_message_iter header;
	struct l_dbus_message_iter array, iter;
	uint8_t endian, message_type, flags, version, field_type;
	uint32_t body_length, serial;

	if (_dbus_message_is_gvariant(message)) {
		uint32_t header_length;

		_gvariant_iter_init(&header, message, "yyyyuuu", NULL,
					message->header, message->header_size);
		if (!message_iter_next_entry(&header, &endian, &message_type,
						&flags, &version, &body_length,
						&serial, &header_length))
			return false;

		_gvariant_iter_init(&header, message, "a(yv)", NULL,
					message->header + 16, header_length);
		_gvariant_iter_enter_array(&header, &array);
	} else {
		_dbus1_iter_init(&header, message, "yyyyuua(yv)", NULL,
				message->header, message->header_size);

		if (!message_iter_next_entry(&header, &endian,
						&message_type, &flags, &version,
						&body_length, &serial, &array))
			return false;
	}

	while (message_iter_next_entry(&array, &field_type, &iter)) {
		if (field_type != type)
			continue;

		return message_iter_next_entry_valist(&iter, args);
	}

	return false;
}

static inline bool get_header_field(struct l_dbus_message *message,
                                                uint8_t type, ...)
{
	va_list args;
	bool result;

	va_start(args, type);
	result = get_header_field_from_iter_valist(message, type, args);
	va_end(args);

	return result;
}

struct l_dbus_message *dbus_message_from_blob(const void *data, size_t size)
{
	const struct dbus_header *hdr = data;
	struct l_dbus_message *message;

	if (unlikely(size < DBUS_HEADER_SIZE))
		return NULL;

	message = l_new(struct l_dbus_message, 1);

	message->refcount = 1;

	message->header_size = align_len(DBUS_HEADER_SIZE +
						hdr->field_length, 8);
	message->header = l_malloc(message->header_size);

	message->body_size = hdr->body_length;
	message->body = l_malloc(message->body_size);

	memcpy(message->header, data, message->header_size);
	memcpy(message->body, data + message->header_size, message->body_size);

	get_header_field(message, DBUS_MESSAGE_FIELD_SIGNATURE,
						&message->signature);

	return message;
}

struct l_dbus_message *dbus_message_build(void *header, size_t header_size,
						void *body, size_t body_size,
						int fds[], uint32_t num_fds)
{
	struct l_dbus_message *message;

	message = l_new(struct l_dbus_message, 1);

	message->refcount = 1;
	message->header_size = header_size;
	message->header = header;
	message->body_size = body_size;
	message->body = body;

	message->num_fds = num_fds;
	memcpy(message->fds, fds, num_fds * sizeof(int));

	get_header_field(message, DBUS_MESSAGE_FIELD_SIGNATURE,
						&message->signature);

	return message;
}

bool dbus_message_compare(struct l_dbus_message *message,
					const void *data, size_t size)
{
	struct l_dbus_message *other;
	bool ret;

	other = dbus_message_from_blob(data, size);

	if (message->signature) {
		if (!other->signature)
			return false;

		if (strcmp(message->signature, other->signature))
			return false;
	} else {
		if (other->signature)
			return false;
	}

	if (message->body_size != other->body_size)
		return false;

	if (message->header_size != other->header_size)
		return false;

	ret = !memcmp(message->body, other->body, message->body_size);

	l_dbus_message_unref(other);

	return ret;
}

static bool append_arguments(struct l_dbus_message *message,
					const char *signature, va_list args)
{
	struct dbus_header *hdr;
	struct dbus1_builder *builder;
	uint32_t size, slen;
	size_t len, pos;
	char *generated_signature;
	char subsig[256];
	const char *sigend;

	slen = strlen(signature);

	size = message->header_size + align_len(slen + 6, 8);

	message->header = l_realloc(message->header, size);

	hdr = message->header;

	pos = DBUS_HEADER_SIZE + align_len(hdr->field_length, 8);
	len = pos + encode_header(8, 'g', signature, slen,
						message->header + pos);

	message->signature = message->header + pos + 5;

	hdr->field_length = len - DBUS_HEADER_SIZE;

	message->header_size = size;

	builder = _dbus1_builder_new();

	while (*signature) {
		const char *str;
		const void *value;

		switch (*signature) {
		case 'o':
		case 's':
		case 'g':
			str = *va_arg(args, const char **);
			if (!_dbus1_builder_append_basic(builder, *signature,
								str))
				goto error;
			break;
		case 'b':
		case 'y':
		case 'n':
		case 'q':
		case 'i':
		case 'u':
		case 'x':
		case 't':
		case 'd':
		case 'h':
			value = va_arg(args, void *);
			if (!_dbus1_builder_append_basic(builder, *signature,
								value))
				goto error;
			break;
		case '(':
			sigend = _dbus_signature_end(signature);
			memcpy(subsig, signature + 1, sigend - signature - 1);
			subsig[sigend - signature - 1] = '\0';

			if (!_dbus1_builder_enter_struct(builder, subsig))
				goto error;

			break;
		case ')':
			if (!_dbus1_builder_leave_struct(builder))
				goto error;

			break;
		default:
			goto error;
		}

		signature += 1;
	}

	generated_signature = _dbus1_builder_finish(builder, &message->body,
							&message->body_size);
	_dbus1_builder_free(builder);

	if (!strcmp(signature, generated_signature))
		return false;

	l_free(generated_signature);

	hdr->body_length = message->body_size;

	return true;

error:
	_dbus1_builder_free(builder);
	return false;
}

LIB_EXPORT bool l_dbus_message_get_error(struct l_dbus_message *message,
					const char **name, const char **text)
{
	struct l_dbus_message_iter iter;
	struct dbus_header *hdr;
	const char *str;

	if (unlikely(!message))
		return false;

	hdr = message->header;

	if (hdr->message_type != DBUS_MESSAGE_TYPE_ERROR)
		return false;

	if (!message->signature)
		return false;

	if (strcmp(message->signature, "s"))
		return false;

	if (_dbus_message_is_gvariant(message))
		_gvariant_iter_init(&iter, message, message->signature, NULL,
					message->body, message->body_size);
	else
		_dbus1_iter_init(&iter, message, message->signature, NULL,
				message->body, message->body_size);

	if (!message_iter_next_entry(&iter, &str))
		return false;

	if (name)
		get_header_field(message, DBUS_MESSAGE_FIELD_ERROR_NAME, name);

	if (text)
		*text = str;

	return true;
}

LIB_EXPORT bool l_dbus_message_get_arguments(struct l_dbus_message *message,
						const char *signature, ...)
{
	struct l_dbus_message_iter iter;
	va_list args;
	bool result;

	if (unlikely(!message))
		return false;

	if (!message->signature) {
		/* An empty signature is valid */
		if (!signature || *signature == '\0')
			return true;

		return false;
	}

	if (!signature || strcmp(message->signature, signature))
		return false;

	if (_dbus_message_is_gvariant(message))
		_gvariant_iter_init(&iter, message, message->signature, NULL,
					message->body, message->body_size);
	else
		_dbus1_iter_init(&iter, message, message->signature, NULL,
				message->body, message->body_size);

	va_start(args, signature);
	result = message_iter_next_entry_valist(&iter, args);
	va_end(args);

	return result;
}

LIB_EXPORT bool l_dbus_message_set_arguments(struct l_dbus_message *message,
						const char *signature, ...)
{
	va_list args;
	bool result;

	if (unlikely(!message))
		return false;

	if (!signature)
		return true;

	va_start(args, signature);
	result = append_arguments(message, signature, args);
	va_end(args);

	return result;
}

LIB_EXPORT const char *l_dbus_message_get_path(struct l_dbus_message *message)
{
	if (unlikely(!message))
		return NULL;

	if (!message->path)
		get_header_field(message, DBUS_MESSAGE_FIELD_PATH,
					&message->path);

	return message->path;
}

LIB_EXPORT const char *l_dbus_message_get_interface(struct l_dbus_message *message)
{
	if (unlikely(!message))
		return NULL;

	if (!message->interface)
		get_header_field(message, DBUS_MESSAGE_FIELD_INTERFACE,
					&message->interface);

	return message->interface;
}

LIB_EXPORT const char *l_dbus_message_get_member(struct l_dbus_message *message)
{
	if (unlikely(!message))
		return NULL;

	if (!message->member)
		get_header_field(message, DBUS_MESSAGE_FIELD_MEMBER,
					&message->member);

	return message->member;
}

LIB_EXPORT const char *l_dbus_message_get_destination(struct l_dbus_message *message)
{
	if (unlikely(!message))
		return NULL;

	if (!message->destination)
		get_header_field(message, DBUS_MESSAGE_FIELD_DESTINATION,
							&message->destination);

	return message->destination;
}

LIB_EXPORT const char *l_dbus_message_get_sender(struct l_dbus_message *message)
{
	if (unlikely(!message))
		return NULL;

	if (!message->sender)
		get_header_field(message, DBUS_MESSAGE_FIELD_SENDER,
					&message->sender);

	return message->sender;
}

LIB_EXPORT const char *l_dbus_message_get_signature(
						struct l_dbus_message *message)
{
	if (unlikely(!message))
		return NULL;

	return message->signature;
}

uint32_t _dbus_message_get_reply_serial(struct l_dbus_message *message)
{
	uint32_t serial;

	if (get_header_field(message, DBUS_MESSAGE_FIELD_REPLY_SERIAL, &serial))
		return serial;

	return 0;
}

enum dbus_message_type _dbus_message_get_type(struct l_dbus_message *message)
{
	struct dbus_header *header;

	header = message->header;
	return header->message_type;
}

LIB_EXPORT char l_dbus_message_iter_get_type(struct l_dbus_message_iter *iter)
{
	if (unlikely(!iter))
		return '\0';

	if (!iter->sig_start)
		return '\0';

	return iter->sig_start[iter->sig_pos];
}

LIB_EXPORT bool l_dbus_message_iter_is_valid(struct l_dbus_message_iter *iter)
{
	if (unlikely(!iter))
		return false;

	if (!iter->sig_start)
		return false;

	if (iter->sig_pos >= iter->sig_len)
		return false;

	return true;
}

LIB_EXPORT bool l_dbus_message_iter_next_entry(struct l_dbus_message_iter *iter,
									...)
{
	va_list args;
	bool result;

	if (unlikely(!iter))
		return false;

	va_start(args, iter);
	result = message_iter_next_entry_valist(iter, args);
	va_end(args);

	return result;
}

LIB_EXPORT bool l_dbus_message_iter_get_variant(
					struct l_dbus_message_iter *iter,
					const char *signature, ...)
{
	va_list args;
	bool result;

	if (unlikely(!iter))
		return false;

	if (!iter->sig_start || strcmp(iter->sig_start, signature))
		return false;

	va_start(args, signature);
	result = message_iter_next_entry_valist(iter, args);
	va_end(args);

	return result;
}
