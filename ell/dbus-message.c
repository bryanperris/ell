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
	uint32_t reply_serial;
	char *destination;
	char *sender;
	int fds[16];
	uint32_t num_fds;

	bool sealed : 1;
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

static struct l_dbus_message *message_new_common(uint8_t type, uint8_t flags,
						uint8_t version)
{
	struct l_dbus_message *message;
	struct dbus_header *hdr;

	message = l_new(struct l_dbus_message, 1);
	message->refcount = 1;

	/*
	 * We allocate the header with the initial 12 bytes (up to the field
	 * length) so that we can store the basic information here
	 */
	message->header = l_realloc(NULL, 12);
	message->header_size = 12;

	hdr = message->header;
	hdr->endian = DBUS_MESSAGE_LITTLE_ENDIAN;
	hdr->message_type = type;
	hdr->flags = 0;
	hdr->version = version;

	return message;
}

struct l_dbus_message *_dbus_message_new_method_call(uint8_t version,
							const char *destination,
							const char *path,
							const char *interface,
							const char *method)
{
	struct l_dbus_message *message;

	message = message_new_common(DBUS_MESSAGE_TYPE_METHOD_CALL, 0, version);

	message->destination = l_strdup(destination);
	message->path = l_strdup(path);
	message->interface = l_strdup(interface);
	message->member = l_strdup(method);

	return message;
}

LIB_EXPORT struct l_dbus_message *l_dbus_message_new_method_call(const char *destination,
                const char *path, const char *interface, const char *method)
{
	return _dbus_message_new_method_call(DBUS_MESSAGE_PROTOCOL_VERSION,
						destination, path,
						interface, method);
}

LIB_EXPORT struct l_dbus_message *l_dbus_message_new_method_return(
					struct l_dbus_message *method_call)
{
	struct l_dbus_message *message;
	struct dbus_header *hdr = method_call->header;
	const char *sender;

	message = message_new_common(DBUS_MESSAGE_TYPE_METHOD_RETURN,
					DBUS_MESSAGE_FLAG_NO_REPLY_EXPECTED,
					hdr->version);

	message->reply_serial = hdr->serial;

	sender = l_dbus_message_get_sender(method_call);
	if (sender)
		message->destination = l_strdup(sender);

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

	if (!message->sealed) {
		l_free(message->destination);
		l_free(message->path);
		l_free(message->interface);
		l_free(message->member);
	}

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

	if (!message->sealed)
		return false;

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

	message->sealed = true;

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

	message->sealed = true;

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

struct builder_driver {
	bool (*append_basic)(struct dbus_builder *, char, const void *);
	bool (*enter_struct)(struct dbus_builder *, const char *);
	bool (*leave_struct)(struct dbus_builder *);
	bool (*enter_dict)(struct dbus_builder *, const char *);
	bool (*leave_dict)(struct dbus_builder *);
	bool (*enter_array)(struct dbus_builder *, const char *);
	bool (*leave_array)(struct dbus_builder *);
	bool (*enter_variant)(struct dbus_builder *, const char *);
	bool (*leave_variant)(struct dbus_builder *);
	char *(*finish)(struct dbus_builder *, void **, size_t *);
	struct dbus_builder *(*new)(void *, size_t);
	void (*free)(struct dbus_builder *);
};

static struct builder_driver dbus1_driver = {
	.append_basic = _dbus1_builder_append_basic,
	.enter_struct = _dbus1_builder_enter_struct,
	.leave_struct = _dbus1_builder_leave_struct,
	.enter_dict = _dbus1_builder_enter_dict,
	.leave_dict = _dbus1_builder_leave_dict,
	.enter_variant = _dbus1_builder_enter_variant,
	.leave_variant = _dbus1_builder_leave_variant,
	.enter_array = _dbus1_builder_enter_array,
	.leave_array = _dbus1_builder_leave_array,
	.finish = _dbus1_builder_finish,
	.new = _dbus1_builder_new,
	.free = _dbus1_builder_free,
};

static struct builder_driver gvariant_driver = {
	.append_basic = _gvariant_builder_append_basic,
	.enter_struct = _gvariant_builder_enter_struct,
	.leave_struct = _gvariant_builder_leave_struct,
	.enter_dict = _gvariant_builder_enter_dict,
	.leave_dict = _gvariant_builder_leave_dict,
	.enter_variant = _gvariant_builder_enter_variant,
	.leave_variant = _gvariant_builder_leave_variant,
	.enter_array = _gvariant_builder_enter_array,
	.leave_array = _gvariant_builder_leave_array,
	.finish = _gvariant_builder_finish,
	.new = _gvariant_builder_new,
	.free = _gvariant_builder_free,
};

static void add_field(struct dbus_builder *builder,
			struct builder_driver *driver,
			uint8_t field, const char *type, const void *value)
{
	driver->enter_struct(builder, "yv");
	driver->append_basic(builder, 'y', &field);
	driver->enter_variant(builder, type);
	driver->append_basic(builder, type[0], value);
	driver->leave_variant(builder);
	driver->leave_struct(builder);
}

static void build_header(struct l_dbus_message *message, const char *signature)
{
	struct dbus_builder *builder;
	struct builder_driver *driver;
	char *generated_signature;
	struct dbus_header *hdr;
	size_t header_size;

	if (_dbus_message_is_gvariant(message))
		driver = &gvariant_driver;
	else
		driver = &dbus1_driver;

	builder = driver->new(message->header, message->header_size);

	if (_dbus_message_is_gvariant(message)) {
		uint32_t field_length = 0;
		driver->append_basic(builder, 'u', &field_length);
	}

	driver->enter_array(builder, "(yv)");

	if (message->path) {
		add_field(builder, driver, DBUS_MESSAGE_FIELD_PATH,
					"o", message->path);
		l_free(message->path);
		message->path = NULL;
	}

	if (message->member) {
		add_field(builder, driver, DBUS_MESSAGE_FIELD_MEMBER,
					"s", message->member);
		l_free(message->member);
		message->member = NULL;
	}

	if (message->interface) {
		add_field(builder, driver, DBUS_MESSAGE_FIELD_INTERFACE,
					"s", message->interface);
		l_free(message->interface);
		message->interface = NULL;
	}

	if (message->destination) {
		add_field(builder, driver, DBUS_MESSAGE_FIELD_DESTINATION,
					"s", message->destination);
		l_free(message->destination);
		message->destination = NULL;
	}

	if (message->reply_serial != 0) {
		add_field(builder, driver, DBUS_MESSAGE_FIELD_REPLY_SERIAL,
					"u", &message->reply_serial);
		message->reply_serial = 0;
	}

	if (message->sender) {
		add_field(builder, driver, DBUS_MESSAGE_FIELD_SENDER,
					"s", message->sender);
		l_free(message->sender);
		message->sender = NULL;
	}

	add_field(builder, driver, DBUS_MESSAGE_FIELD_SIGNATURE,
			"g", signature);

	driver->leave_array(builder);

	generated_signature = driver->finish(builder, &message->header,
						&header_size);
	l_free(generated_signature);

	driver->free(builder);

	hdr = message->header;

	if (_dbus_message_is_gvariant(message))
		hdr->field_length = header_size - 16;

	hdr->body_length = message->body_size;

	/* We must align the end of the header to an 8-byte boundary */
	message->header_size = align_len(header_size, 8);
	message->header = l_realloc(message->header, message->header_size);
	memset(message->header + header_size, 0,
			message->header_size - header_size);
}

static bool append_arguments(struct l_dbus_message *message,
					const char *signature, va_list args)
{
	const char *s = signature;
	struct dbus_builder *builder;
	struct builder_driver *driver;
	char *generated_signature;
	char subsig[256];
	const char *sigend;

	if (_dbus_message_is_gvariant(message))
		driver = &gvariant_driver;
	else
		driver = &dbus1_driver;

	builder = driver->new(NULL, 0);

	while (*s) {
		const char *str;
		const void *value;

		switch (*s) {
		case 'o':
		case 's':
		case 'g':
			str = *va_arg(args, const char **);

			if (!driver->append_basic(builder, *s, str))
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

			if (!driver->append_basic(builder, *s, value))
				goto error;
			break;
		case '(':
			sigend = _dbus_signature_end(s);
			memcpy(subsig, s + 1, sigend - s - 1);
			subsig[sigend - s - 1] = '\0';

			if (!driver->enter_struct(builder, subsig))
				goto error;

			break;
		case ')':
			if (!driver->leave_struct(builder))
				goto error;

			break;
		default:
			goto error;
		}

		s += 1;
	}

	generated_signature = driver->finish(builder, &message->body,
						&message->body_size);
	driver->free(builder);

	if (strcmp(signature, generated_signature))
		return false;

	l_free(generated_signature);

	build_header(message, signature);
	message->sealed = true;

	get_header_field(message, DBUS_MESSAGE_FIELD_SIGNATURE,
						&message->signature);

	return true;

error:
	driver->free(builder);
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

	if (!message->sealed)
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
	if (unlikely(!message))
		return 0;

	if (message->reply_serial == 0)
		get_header_field(message, DBUS_MESSAGE_FIELD_REPLY_SERIAL,
					&message->reply_serial);

	return message->reply_serial;
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
