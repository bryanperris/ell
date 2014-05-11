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
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "util.h"
#include "io.h"
#include "queue.h"
#include "hashmap.h"
#include "dbus.h"
#include "private.h"
#include "dbus-private.h"

#define DEFAULT_SYSTEM_BUS_ADDRESS "unix:path=/var/run/dbus/system_bus_socket"

#define DBUS_SERVICE_DBUS	"org.freedesktop.DBus"

#define DBUS_PATH_DBUS		"/org/freedesktop/DBus"

#define DBUS_INTERFACE_DBUS		"org.freedesktop.DBus"
#define DBUS_INTERFACE_INTROSPECTABLE	"org.freedesktop.DBus.Introspectable"
#define DBUS_INTERFACE_PROPERTIES	"org.freedesktop.DBus.Properties"

#define DBUS_MESSAGE_LITTLE_ENDIAN	('l')
#define DBUS_MESSAGE_BIG_ENDIAN		('B')

#define DBUS_MESSAGE_PROTOCOL_VERSION	1

#define DBUS_MESSAGE_TYPE_METHOD_CALL	1
#define DBUS_MESSAGE_TYPE_METHOD_RETURN	2
#define DBUS_MESSAGE_TYPE_ERROR		3
#define DBUS_MESSAGE_TYPE_SIGNAL	4

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

enum auth_state {
	WAITING_FOR_OK,
	WAITING_FOR_AGREE_UNIX_FD,
	SETUP_DONE
};

struct l_dbus {
	struct l_io *io;
	char *guid;
	void *auth_command;
	enum auth_state auth_state;
	bool negotiate_unix_fd;
	bool support_unix_fd;
	bool is_ready;
	unsigned int next_id;
	uint32_t next_serial;
	struct l_queue *message_queue;
	struct l_hashmap *message_list;
	struct l_hashmap *signal_list;
	l_dbus_ready_func_t ready_handler;
	l_dbus_destroy_func_t ready_destroy;
	void *ready_data;
	l_dbus_disconnect_func_t disconnect_handler;
	l_dbus_destroy_func_t disconnect_destroy;
	void *disconnect_data;
	l_dbus_debug_func_t debug_handler;
	l_dbus_destroy_func_t debug_destroy;
	void *debug_data;
};

struct l_dbus_message {
	int refcount;
	void *header;
	size_t header_size;
	const char *signature;
	uint32_t unix_fds;
	void *body;
	size_t body_size;
	int fds[16];
	uint32_t num_fds;
};

struct message_iter {
	struct l_dbus_message *message;
	void *dummy2;
	const char *signature;
	const char *end;
	const void *data;
	size_t len;
	size_t pos;
};

struct message_callback {
	uint32_t serial;
	struct l_dbus_message *message;
	l_dbus_message_func_t callback;
	l_dbus_destroy_func_t destroy;
	void *user_data;
};

struct signal_callback {
	unsigned int id;
	l_dbus_message_func_t callback;
	l_dbus_destroy_func_t destroy;
	void *user_data;
};

struct dbus_header {
	uint8_t  endian;
	uint8_t  message_type;
	uint8_t  flags;
	uint8_t  version;
	uint32_t body_length;
	uint32_t serial;
	uint32_t field_length;
} __attribute__ ((packed));
#define DBUS_HEADER_SIZE 16

static void message_queue_destroy(void *data)
{
	struct message_callback *callback = data;

	l_dbus_message_unref(callback->message);

	if (callback->destroy)
		callback->destroy(callback->user_data);

	l_free(callback);
}

static void message_list_destroy(void *value)
{
	message_queue_destroy(value);
}

static void signal_list_destroy(void *value)
{
	struct signal_callback *callback = value;

	if (callback->destroy)
		callback->destroy(callback->user_data);

	l_free(callback);
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

#define get_u8(ptr)		(*(uint8_t *) (ptr))
#define get_u16(ptr)		(*(uint16_t *) (ptr))
#define get_u32(ptr)		(*(uint32_t *) (ptr))
#define get_u64(ptr)		(*(uint64_t *) (ptr))
#define get_s16(ptr)		(*(int16_t *) (ptr))
#define get_s32(ptr)		(*(int32_t *) (ptr))
#define get_s64(ptr)		(*(int64_t *) (ptr))
#define put_u8(ptr,val)		(*((uint8_t *) (ptr)) = (val))
#define put_u16(ptr,val)	(*((uint16_t *) (ptr)) = (val))
#define put_u32(ptr, val)	(*((uint32_t *) (ptr)) = (val))
#define put_u64(ptr, val)	(*((uint64_t *) (ptr)) = (val))
#define put_s16(ptr, val)	(*((int16_t *) (ptr)) = (val))
#define put_s32(ptr, val)	(*((int32_t *) (ptr)) = (val))
#define put_s64(ptr, val)	(*((int64_t *) (ptr)) = (val))

static inline void message_iter_init(struct message_iter *iter,
			struct l_dbus_message *message, const char *signature,
			const void *data, size_t len, size_t pos)
{
	iter->message = message;
	iter->signature = signature;
	iter->end = NULL;
	iter->data = data;
	iter->len = pos + len;
	iter->pos = pos;
}

static inline size_t calc_len_one(const char signature,
					const void *data, size_t pos)
{
	switch (signature) {
	case 'o':
	case 's':
		return align_len(pos, 4) - pos +
				get_u32(data + align_len(pos, 4)) + 5;
	case 'g':
		return align_len(pos, 1) - pos +
				get_u8(data + align_len(pos, 1)) + 2;
	case 'y':
		return align_len(pos, 1) + 1 - pos;
	case 'n':
	case 'q':
		return align_len(pos, 2) + 2 - pos;
	case 'b':
	case 'i':
	case 'u':
	case 'h':
		return align_len(pos, 4) + 4 - pos;
	case 'x':
	case 't':
	case 'd':
		return align_len(pos, 8) + 8 - pos;
	case 'a':
		return get_u32(data + align_len(pos, 4)) + 4;
	case '(':
	case '{':
		return align_len(pos, 8) - pos;
	}

	return 0;
}

static inline size_t calc_len(const char *signature,
					const void *data, size_t pos)
{
	const char *ptr = signature;
	unsigned int indent = 0;
	size_t len = 0;
	char expect;

	switch (*signature) {
	case '(':
		expect = ')';
		break;
	case '{':
		expect = '}';
		break;
	case 'v':
		len = calc_len_one('g', data, pos);
		return len + calc_len(data + pos + 1, data, pos + len);
	default:
		return calc_len_one(*signature, data, pos);
	}

	for (ptr = signature; *ptr != '\0'; ptr++) {
		if (*ptr == *signature)
			indent++;
		else if (*ptr == expect)
			if (!--indent)
				break;
		if (*ptr == 'v') {
			size_t siglen = calc_len_one('g', data, pos + len);
			len += calc_len(data + pos + len + 1, data,
							pos + len + siglen);
		} else
			len += calc_len_one(*ptr, data, pos + len);
        }

	return len;
}

static bool message_iter_next_entry_valist(struct message_iter *iter,
							va_list args)
{
	const char *signature = iter->signature;

	while (*signature) {
		struct message_iter *sub_iter;
		unsigned char indent = 0;
		size_t pos, len;
		const char *str_val;
		uint8_t uint8_val;
		uint16_t uint16_val;
		uint32_t uint32_val;
		uint64_t uint64_val;
		int16_t int16_val;
		int32_t int32_val;
		int64_t int64_val;
		int fd;

		switch (*signature) {
		case 'o':
		case 's':
			pos = align_len(iter->pos, 4);
			if (pos + 5 > iter->len)
				return false;
			uint32_val = get_u32(iter->data + pos);
			str_val = iter->data + pos + 4;
			*va_arg(args, const void **) = str_val;
			iter->pos = pos + uint32_val + 5;
			break;
		case 'g':
			pos = align_len(iter->pos, 1);
			if (pos + 2 > iter->len)
				return false;
			uint8_val = get_u8(iter->data + pos);
			str_val = iter->data + pos + 1;
			*va_arg(args, const void **) = str_val;
			iter->pos = pos + uint8_val + 2;
			break;
		case 'b':
			pos = align_len(iter->pos, 4);
			if (pos + 4 > iter->len)
				return false;
			uint32_val = get_u32(iter->data + pos);
			*va_arg(args, bool *) = !!uint32_val;
			iter->pos = pos + 4;
			break;
		case 'y':
			pos = align_len(iter->pos, 1);
			if (pos + 1 > iter->len)
				return false;
			uint8_val = get_u8(iter->data + pos);
			*va_arg(args, uint8_t *) = uint8_val;
			iter->pos = pos + 1;
			break;
		case 'n':
			pos = align_len(iter->pos, 2);
			if (pos + 2 > iter->len)
				return false;
			int16_val = get_s16(iter->data + pos);
			*va_arg(args, int16_t *) = int16_val;
			iter->pos = pos + 2;
			break;
		case 'q':
			pos = align_len(iter->pos, 2);
			if (pos + 2 > iter->len)
				return false;
			uint16_val = get_u16(iter->data + pos);
			*va_arg(args, uint16_t *) = uint16_val;
			iter->pos = pos + 2;
			break;
		case 'i':
			pos = align_len(iter->pos, 4);
			if (pos + 4 > iter->len)
				return false;
			int32_val = get_s32(iter->data + pos);
			*va_arg(args, int32_t *) = int32_val;
			iter->pos = pos + 4;
			break;
		case 'u':
			pos = align_len(iter->pos, 4);
			if (pos + 4 > iter->len)
				return false;
			uint32_val = get_u32(iter->data + pos);
			*va_arg(args, uint32_t *) = uint32_val;
			iter->pos = pos + 4;
			break;
		case 'x':
			pos = align_len(iter->pos, 8);
			if (pos + 8 > iter->len)
				return false;
			int64_val = get_s64(iter->data + pos);
			*va_arg(args, int64_t *) = int64_val;
			iter->pos = pos + 8;
			break;
		case 't':
			pos = align_len(iter->pos, 8);
			if (pos + 8 > iter->len)
				return false;
			uint64_val = get_u64(iter->data + pos);
			*va_arg(args, uint64_t *) = uint64_val;
			iter->pos = pos + 8;
			break;
		case 'd':
			pos = align_len(iter->pos, 8);
			if (pos + 8 > iter->len)
				return false;
			uint64_val = get_u64(iter->data + pos);
			*va_arg(args, double *) = (double) uint64_val;
			iter->pos = pos + 8;
			break;
		case 'h':
			pos = align_len(iter->pos, 4);
			if (pos + 4 > iter->len)
				return false;
			uint32_val = get_u32(iter->data + pos);
			if (uint32_val < iter->message->num_fds)
				fd = fcntl(iter->message->fds[uint32_val],
							F_DUPFD_CLOEXEC, 3);
			else
				fd = -1;
			*va_arg(args, int *) = fd;
			iter->pos = pos + 4;
			break;
		case '(':
		case '{':
			indent++;
			pos = align_len(iter->pos, 8);
			iter->pos = pos;
			break;
		case ')':
		case '}':
			indent--;
			break;
		case 'a':
			pos = align_len(iter->pos, 4);
			if (pos + 4 > iter->len)
				return false;
			uint32_val = get_u32(iter->data + pos);
			sub_iter = va_arg(args, void *);
			message_iter_init(sub_iter, iter->message,
						signature + 1, iter->data,
						uint32_val, pos + 4);
			iter->pos = pos + uint32_val + 4;
			signature = _dbus_signature_end(signature + 1);
			sub_iter->end = signature;
			break;
		case 'v':
			pos = align_len(iter->pos, 1);
			if (pos + 2 > iter->len)
				return false;
			uint8_val = get_u8(iter->data + pos);
			str_val = iter->data + pos + 1;
			len = calc_len(str_val, iter->data,
						pos + uint8_val + 2);
			sub_iter = va_arg(args, void *);
			message_iter_init(sub_iter, iter->message,
						str_val, iter->data,
						len, pos + uint8_val + 2);
			iter->pos = pos + uint8_val + 2 + len;
			break;
		default:
			return false;
		}

		if (signature == iter->end)
			break;

		signature++;
	}

	return true;
}

static inline bool message_iter_next_entry(struct message_iter *iter, ...)
{
	va_list args;
	bool result;

        va_start(args, iter);
	result = message_iter_next_entry_valist(iter, args);
	va_end(args);

	return result;
}

static bool send_message_to_fd(int fd, struct l_dbus_message *message,
							uint32_t serial)
{
	struct dbus_header *hdr = message->header;
	struct msghdr msg;
	struct iovec iov[2];
	ssize_t len;

	hdr->serial = serial;

	iov[0].iov_base = message->header;
	iov[0].iov_len  = message->header_size;
	iov[1].iov_base = message->body;
	iov[1].iov_len  = message->body_size;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	len = sendmsg(fd, &msg, 0);
	if (len < 0)
		return false;

	return true;
}

static bool message_write_handler(struct l_io *io, void *user_data)
{
	struct l_dbus *dbus = user_data;
	struct l_dbus_message *message;
	struct message_callback *callback;
	int fd;

	callback = l_queue_pop_head(dbus->message_queue);
	if (!callback)
		return false;

	message = callback->message;

	fd = l_io_get_fd(io);

	if (!send_message_to_fd(fd, message, callback->serial))
		return false;

	l_util_hexdump_two(false, message->header, message->header_size,
					message->body, message->body_size,
					dbus->debug_handler, dbus->debug_data);

	l_hashmap_insert(dbus->message_list,
				L_UINT_TO_PTR(callback->serial), callback);

	if (l_queue_isempty(dbus->message_queue))
		return false;

	/* Only continue sending messges if the connection is ready */
	return dbus->is_ready;
}

static bool get_header_field_from_iter_valist(struct message_iter *header,
						uint8_t type, va_list args)
{
	struct message_iter array, iter;
	uint8_t endian, message_type, flags, version, field_type;
	uint32_t body_length, serial;

	if (!message_iter_next_entry(header, &endian,
					&message_type, &flags, &version,
					&body_length, &serial, &array))
		return false;

	while (message_iter_next_entry(&array, &field_type, &iter)) {
		if (field_type != type)
			continue;

		return message_iter_next_entry_valist(&iter, args);
	}

	return false;
}

static bool get_header_field_from_iter(struct message_iter *header,
						uint8_t type, ...)
{
	va_list args;
	bool result;

	va_start(args, type);
	result = get_header_field_from_iter_valist(header, type, args);
	va_end(args);

	return result;
}

static inline bool get_header_field(struct l_dbus_message *message,
                                                uint8_t type, ...)
{
	struct message_iter header;
	va_list args;
	bool result;

	message_iter_init(&header, message, "yyyyuua(yv)",
				message->header, message->header_size, 0);

	va_start(args, type);
	result = get_header_field_from_iter_valist(&header, type, args);
	va_end(args);

	return result;
}

struct l_dbus_message *dbus_message_build(const void *data, size_t size)
{
	const struct dbus_header *hdr = data;
	struct l_dbus_message *message;

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

bool dbus_message_compare(struct l_dbus_message *message,
					const void *data, size_t size)
{
	const struct dbus_header *hdr = data;
	struct message_iter header;
	const char *signature;
	size_t header_size;
	bool result;

	header_size = align_len(DBUS_HEADER_SIZE + hdr->field_length, 8);

	message_iter_init(&header, NULL, "yyyyuua(yv)", data, header_size, 0);

	result = get_header_field_from_iter(&header,
				DBUS_MESSAGE_FIELD_SIGNATURE, &signature);

	if (result) {
		if (!message->signature)
			return false;

		if (strcmp(signature, message->signature))
			return false;
	} else if (message->signature)
		return false;

	if (message->body_size != size - header_size)
		return false;

	if (!message->body_size)
		return true;

	return !memcmp(message->body, data + header_size, size - header_size);
}

static struct l_dbus_message *receive_message_from_fd(int fd)
{
	struct l_dbus_message *message;
	struct dbus_header hdr;
	struct msghdr msg;
	struct iovec iov[2];
	struct cmsghdr *cmsg;
	ssize_t len;

	message = l_new(struct l_dbus_message, 1);

	message->refcount = 1;

	len = recv(fd, &hdr, 16, MSG_PEEK);
	if (len != 16)
		return NULL;

	message->header_size = align_len(DBUS_HEADER_SIZE +
						hdr.field_length, 8);
	message->header = l_malloc(message->header_size);

	message->body_size = hdr.body_length;
	message->body = l_malloc(message->body_size);

	iov[0].iov_base = message->header;
	iov[0].iov_len  = message->header_size;
	iov[1].iov_base = message->body;
	iov[1].iov_len  = message->body_size;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	msg.msg_control = &message->fds;
	msg.msg_controllen = CMSG_SPACE(16 * sizeof(int));

	len = recvmsg(fd, &msg, MSG_CMSG_CLOEXEC);
	if (len < 0)
		return NULL;

	get_header_field(message, DBUS_MESSAGE_FIELD_UNIX_FDS,
						&message->unix_fds);

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg;
				cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		unsigned int i;

		if (cmsg->cmsg_level != SOL_SOCKET ||
					cmsg->cmsg_type != SCM_RIGHTS)
			continue;

		message->num_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);

		memcpy(message->fds, CMSG_DATA(cmsg),
					message->num_fds * sizeof(int));

		/* Set FD_CLOEXEC on all file descriptors */
		for (i = 0; i < message->num_fds; i++) {
			long flags;

			flags = fcntl(fd, F_GETFD, NULL);
			if (flags < 0)
				continue;

			if (!(flags & FD_CLOEXEC))
				fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
                }
	}

	get_header_field(message, DBUS_MESSAGE_FIELD_SIGNATURE,
						&message->signature);

	return message;
}

static void handle_method_return(struct l_dbus *dbus,
					struct l_dbus_message *message)
{
	struct message_callback *callback;
	uint32_t reply_serial;

	if (!get_header_field(message, DBUS_MESSAGE_FIELD_REPLY_SERIAL,
							&reply_serial))
		return;

	callback = l_hashmap_remove(dbus->message_list,
					L_UINT_TO_PTR(reply_serial));
	if (!callback)
		return;

	if (callback->callback)
		callback->callback(message, callback->user_data);

	if (callback->destroy)
		callback->destroy(callback->user_data);

	message_queue_destroy(callback);
}

static void handle_error(struct l_dbus *dbus, struct l_dbus_message *message)
{
	struct message_callback *callback;
	uint32_t reply_serial;

	if (!get_header_field(message, DBUS_MESSAGE_FIELD_REPLY_SERIAL,
							&reply_serial))
		return;

	callback = l_hashmap_remove(dbus->message_list,
					L_UINT_TO_PTR(reply_serial));
	if (!callback)
		return;

	if (callback->callback)
		callback->callback(message, callback->user_data);

	if (callback->destroy)
		callback->destroy(callback->user_data);

	message_queue_destroy(callback);
}

static void process_signal(const void *key, void *value, void *user_data)
{
	struct signal_callback *callback = value;
	struct l_dbus_message *message = user_data;

	if (callback->callback)
		callback->callback(message, callback->user_data);
}

static void handle_signal(struct l_dbus *dbus, struct l_dbus_message *message)
{
	l_hashmap_foreach(dbus->signal_list, process_signal, message);
}

static bool message_read_handler(struct l_io *io, void *user_data)
{
	struct l_dbus *dbus = user_data;
	struct l_dbus_message *message;
	struct dbus_header *hdr;
	int fd;

	fd = l_io_get_fd(io);

	message = receive_message_from_fd(fd);
	if (!message)
		return false;

	l_util_hexdump_two(true, message->header, message->header_size,
					message->body, message->body_size,
					dbus->debug_handler, dbus->debug_data);

	hdr = message->header;

	switch (hdr->message_type) {
	case DBUS_MESSAGE_TYPE_METHOD_RETURN:
		handle_method_return(dbus, message);
		break;
	case DBUS_MESSAGE_TYPE_ERROR:
		handle_error(dbus, message);
		break;
	case DBUS_MESSAGE_TYPE_SIGNAL:
		handle_signal(dbus, message);
		break;
	}

	l_dbus_message_unref(message);

	return true;
}

static uint32_t send_message(struct l_dbus *dbus, bool priority,
				struct l_dbus_message *message,
				l_dbus_message_func_t function,
				void *user_data, l_dbus_destroy_func_t destroy)
{
	struct message_callback *callback;

	callback = l_new(struct message_callback, 1);

	callback->serial = dbus->next_serial++;
	callback->message = l_dbus_message_ref(message);
	callback->callback = function;
	callback->destroy = destroy;
	callback->user_data = user_data;

	if (priority) {
		l_queue_push_head(dbus->message_queue, callback);

		l_io_set_write_handler(dbus->io, message_write_handler,
							dbus, NULL);

		return callback->serial;
	}

	l_queue_push_tail(dbus->message_queue, callback);

	if (dbus->is_ready)
		l_io_set_write_handler(dbus->io, message_write_handler,
							dbus, NULL);

	return callback->serial;
}

static void hello_callback(struct l_dbus_message *message, void *user_data)
{
	struct l_dbus *dbus = user_data;

	dbus->is_ready = true;

	if (dbus->ready_handler)
		dbus->ready_handler(dbus->ready_data);

	/* Check for messages added before the connection was ready */
	if (l_queue_isempty(dbus->message_queue))
		return;

	l_io_set_write_handler(dbus->io, message_write_handler, dbus, NULL);
}

static bool auth_write_handler(struct l_io *io, void *user_data)
{
	struct l_dbus *dbus = user_data;
	ssize_t written, len;
	int fd;

	fd = l_io_get_fd(io);

	if (!dbus->auth_command)
		return false;

	len = strlen(dbus->auth_command);
	if (!len)
		return false;

	written = send(fd, dbus->auth_command, len, 0);

	l_util_hexdump(false, dbus->auth_command, written,
					dbus->debug_handler, dbus->debug_data);

	l_free(dbus->auth_command);
	dbus->auth_command = NULL;

	if (dbus->auth_state == SETUP_DONE) {
		struct l_dbus_message *message;

		l_io_set_read_handler(dbus->io, message_read_handler,
							dbus, NULL);

		message = l_dbus_message_new_method_call(DBUS_SERVICE_DBUS,
				DBUS_PATH_DBUS, DBUS_INTERFACE_DBUS, "Hello");

		send_message(dbus, true, message, hello_callback, dbus, NULL);

		l_dbus_message_unref(message);

		return true;
	}

	return false;
}

static bool auth_read_handler(struct l_io *io, void *user_data)
{
	struct l_dbus *dbus = user_data;
	char buffer[64];
	char *ptr, *end;
	ssize_t offset, len;
	int fd;

	fd = l_io_get_fd(io);

	ptr = buffer;
	offset = 0;

	while (1) {
		len = recv(fd, ptr + offset, sizeof(buffer) - offset, 0);
		if (len < 1)
			break;

		offset += len;
	}

	ptr = buffer;
	len = offset;

	if (!ptr || len < 3)
		return true;

	end = strstr(ptr, "\r\n");
	if (!end)
		return true;

	if (end - ptr + 2 != len)
		return true;

	l_util_hexdump(true, ptr, len, dbus->debug_handler, dbus->debug_data);

	end = '\0';

	switch (dbus->auth_state) {
	case WAITING_FOR_OK:
		if (!strncmp(ptr, "OK ", 3)) {
			enum auth_state state;
			const char *command;

			if (dbus->negotiate_unix_fd) {
				command = "NEGOTIATE_UNIX_FD\r\n";
				state = WAITING_FOR_AGREE_UNIX_FD;
			} else {
				command = "BEGIN\r\n";
				state = SETUP_DONE;
			}

			dbus->guid = l_strdup(ptr + 3);

			dbus->auth_command = l_strdup(command);
			dbus->auth_state = state;
			break;
		} else if (!strncmp(ptr, "REJECTED ", 9)) {
			static const char *command = "AUTH ANONYMOUS\r\n";

			dbus->negotiate_unix_fd = false;

			dbus->auth_command = l_strdup(command);
			dbus->auth_state = WAITING_FOR_OK;
		}
		break;

	case WAITING_FOR_AGREE_UNIX_FD:
		if (!strncmp(ptr, "AGREE_UNIX_FD", 13)) {
			static const char *command = "BEGIN\r\n";

			dbus->support_unix_fd = true;

			dbus->auth_command = l_strdup(command);
			dbus->auth_state = SETUP_DONE;
			break;
		} else if (!strncmp(ptr, "ERROR", 5)) {
			static const char *command = "BEGIN\r\n";

			dbus->support_unix_fd = false;

			dbus->auth_command = l_strdup(command);
			dbus->auth_state = SETUP_DONE;
			break;
		}
		break;

	case SETUP_DONE:
		break;
	}

	l_io_set_write_handler(io, auth_write_handler, dbus, NULL);

	return true;
}

static void disconnect_handler(struct l_io *io, void *user_data)
{
	struct l_dbus *dbus = user_data;

	dbus->is_ready = false;

	l_util_debug(dbus->debug_handler, dbus->debug_data, "disconnect");

	if (dbus->disconnect_handler)
		dbus->disconnect_handler(dbus->disconnect_data);
}

static struct l_dbus *setup_connection(int fd, const char *guid)
{
	static const unsigned char creds = 0x00;
	char uid[6], hexuid[12], *ptr = hexuid;
	struct l_dbus *dbus;
	ssize_t written;
	unsigned int i;
	long flags;

	if (snprintf(uid, sizeof(uid), "%d", geteuid()) < 1) {
		close(fd);
		return NULL;
	}

	for (i = 0; i < strlen(uid); i++)
		ptr += sprintf(ptr, "%02x", uid[i]);

	/* Send special credentials-passing nul byte */
	written = send(fd, &creds, 1, 0);
	if (written < 1) {
		close(fd);
		return NULL;
	}

	flags = fcntl(fd, F_GETFL, NULL);
	if (flags < 0) {
		close(fd);
		return NULL;
	}

	/* Input handling requires non-blocking socket */
	if (!(flags & O_NONBLOCK)) {
		if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
			close(fd);
			return NULL;
		}
	}

	dbus = l_new(struct l_dbus, 1);

	dbus->io = l_io_new(fd);
	dbus->guid = l_strdup(guid);

	dbus->auth_command = l_strdup_printf("AUTH EXTERNAL %s\r\n", hexuid);
	dbus->auth_state = WAITING_FOR_OK;

	dbus->negotiate_unix_fd = true;
	dbus->support_unix_fd = false;
	dbus->is_ready = false;
	dbus->next_id = 1;
	dbus->next_serial = 1;

	dbus->message_queue = l_queue_new();
	dbus->message_list = l_hashmap_new();
	dbus->signal_list = l_hashmap_new();

	l_io_set_close_on_destroy(dbus->io, true);

	l_io_set_disconnect_handler(dbus->io, disconnect_handler, dbus, NULL);

	l_io_set_read_handler(dbus->io, auth_read_handler, dbus, NULL);
	l_io_set_write_handler(dbus->io, auth_write_handler, dbus, NULL);

	return dbus;
}

static struct l_dbus *setup_unix(char *params)
{
	char *path = NULL, *guid = NULL;
	bool abstract = false;
	struct sockaddr_un addr;
	size_t len;
	int fd;

	while (params) {
		char *key = strsep(&params, ",");
		char *value;

		if (!key)
			break;

		value = strchr(key, '=');
		if (!value)
			continue;

		*value++ = '\0';

		if (!strcmp(key, "path")) {
			path = value;
			abstract = false;
		} else if (!strcmp(key, "abstract")) {
			path = value;
			abstract = true;
		} else if (!strcmp(key, "guid"))
			guid = value;
	}

	if (!path)
		return NULL;

	fd = socket(PF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return NULL;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	len = strlen(path);

	if (abstract) {
		if (len > sizeof(addr.sun_path) - 1) {
			close(fd);
			return NULL;
		}

		addr.sun_path[0] = '\0';
		strncpy(addr.sun_path + 1, path, len);
		len++;
	} else {
		if (len > sizeof(addr.sun_path)) {
			close(fd);
			return NULL;
		}

		strncpy(addr.sun_path, path, len);
	}

	if (connect(fd, (struct sockaddr *) &addr,
				sizeof(addr.sun_family) + len) < 0) {
		close(fd);
		return NULL;
	}

	return setup_connection(fd, guid);
}

static struct l_dbus *setup_address(const char *address)
{
	struct l_dbus *dbus = NULL;
	char *address_copy;

	address_copy = strdupa(address);

	while (address_copy) {
		char *transport = strsep(&address_copy, ";");
		char *params;

		if (!transport)
			break;

		params = strchr(transport, ':');
		if (params)
			*params++ = '\0';

		if (!strcmp(transport, "unix")) {
			/* Function will modify params string */
			dbus = setup_unix(params);
			break;
		}
	}

	return dbus;
}

LIB_EXPORT struct l_dbus *l_dbus_new(enum l_dbus_bus bus)
{
	const char *address;

	switch (bus) {
	case L_DBUS_SYSTEM_BUS:
		address = getenv("DBUS_SYSTEM_BUS_ADDRESS");
		if (!address)
			address = DEFAULT_SYSTEM_BUS_ADDRESS;
		break;
	case L_DBUS_SESSION_BUS:
		address = getenv("DBUS_SESSION_BUS_ADDRESS");
		if (!address)
			return NULL;
		break;
	default:
		return NULL;
	}

	return setup_address(address);
}

LIB_EXPORT void l_dbus_destroy(struct l_dbus *dbus)
{
	if (unlikely(!dbus))
		return;

	if (dbus->ready_destroy)
		dbus->ready_destroy(dbus->ready_data);

	l_hashmap_destroy(dbus->signal_list, signal_list_destroy);
	l_hashmap_destroy(dbus->message_list, message_list_destroy);
	l_queue_destroy(dbus->message_queue, message_queue_destroy);

	l_io_destroy(dbus->io);

	if (dbus->disconnect_destroy)
		dbus->disconnect_destroy(dbus->disconnect_data);

	if (dbus->debug_destroy)
		dbus->debug_destroy(dbus->debug_data);

	l_free(dbus->guid);
	l_free(dbus);
}

LIB_EXPORT bool l_dbus_set_ready_handler(struct l_dbus *dbus,
				l_dbus_ready_func_t function,
				void *user_data, l_dbus_destroy_func_t destroy)
{
	if (unlikely(!dbus))
		return false;

	if (dbus->ready_destroy)
		dbus->ready_destroy(dbus->ready_data);

	dbus->ready_handler = function;
	dbus->ready_destroy = destroy;
	dbus->ready_data = user_data;

	return true;
}

LIB_EXPORT bool l_dbus_set_disconnect_handler(struct l_dbus *dbus,
				l_dbus_disconnect_func_t function,
				void *user_data, l_dbus_destroy_func_t destroy)
{
	if (unlikely(!dbus))
		return false;

	if (dbus->disconnect_destroy)
		dbus->disconnect_destroy(dbus->disconnect_data);

	dbus->disconnect_handler = function;
	dbus->disconnect_destroy = destroy;
	dbus->disconnect_data = user_data;

	return true;
}

LIB_EXPORT bool l_dbus_set_debug(struct l_dbus *dbus,
				l_dbus_debug_func_t function,
				void *user_data, l_dbus_destroy_func_t destroy)
{
	if (unlikely(!dbus))
		return false;

	if (dbus->debug_destroy)
		dbus->debug_destroy(dbus->debug_data);

	dbus->debug_handler = function;
	dbus->debug_destroy = destroy;
	dbus->debug_data = user_data;

	//l_io_set_debug(dbus->io, function, user_data, NULL);

	return true;
}

LIB_EXPORT uint32_t l_dbus_send(struct l_dbus *dbus,
				struct l_dbus_message *message,
				l_dbus_message_func_t function,
				void *user_data, l_dbus_destroy_func_t destroy)
{
	if (unlikely(!dbus || !message))
		return 0;

	return send_message(dbus, false, message, function, user_data, destroy);
}

static bool remove_entry(void *data, void *user_data)
{
	struct message_callback *callback = data;
	uint32_t serial = L_PTR_TO_UINT(user_data);

	if (callback->serial == serial) {
		message_queue_destroy(callback);
		return true;
	}

	return false;
}

LIB_EXPORT bool l_dbus_cancel(struct l_dbus *dbus, uint32_t serial)
{
	struct message_callback *callback;
	unsigned int count;

	if (unlikely(!dbus || !serial))
		return false;

	callback = l_hashmap_remove(dbus->message_list, L_UINT_TO_PTR(serial));
        if (callback) {
		message_queue_destroy(callback);
		return true;
	}

	count = l_queue_foreach_remove(dbus->message_queue, remove_entry,
							L_UINT_TO_PTR(serial));
	if (!count)
		return false;

	return true;
}

LIB_EXPORT unsigned int l_dbus_register(struct l_dbus *dbus,
				l_dbus_message_func_t function,
				void *user_data, l_dbus_destroy_func_t destroy)
{
	struct signal_callback *callback;

	if (unlikely(!dbus))
		return 0;

	callback = l_new(struct signal_callback, 1);

	callback->id = dbus->next_id++;
	callback->callback = function;
	callback->destroy = destroy;
	callback->user_data = user_data;

	l_hashmap_insert(dbus->signal_list,
				L_UINT_TO_PTR(callback->id), callback);

	return callback->id;
}

LIB_EXPORT bool l_dbus_unregister(struct l_dbus *dbus, unsigned int id)
{
	struct signal_callback *callback;

	if (unlikely(!dbus || !id))
		return false;

	callback = l_hashmap_remove(dbus->signal_list, L_UINT_TO_PTR(id));
	if (!callback)
		return false;

	signal_list_destroy(callback);

	return true;
}

static inline size_t body_realloc(struct l_dbus_message *message,
					size_t len, unsigned int boundary)
{
	size_t size = align_len(message->body_size, boundary);

	if (size + len > message->body_size) {
		message->body = l_realloc(message->body, size + len);

		if (size - message->body_size > 0)
			memset(message->body + message->body_size, 0,
						size - message->body_size);

		message->body_size = size + len;
	}

	return size;
}

static bool append_arguments(struct l_dbus_message *message,
					const char *signature, va_list args)
{
	struct dbus_header *hdr;
	uint32_t size, slen;
	size_t len, pos;

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

	while (*signature) {
		const char *str;
		uint8_t uint8_val;
		uint16_t uint16_val;
		uint32_t uint32_val;
		uint64_t uint64_val;
		int16_t int16_val;
		int32_t int32_val;
		int64_t int64_val;
		double double_val;

		switch (*signature++) {
		case 'o':
		case 's':
			str = *va_arg(args, const char **);
			len = strlen(str);
			pos = body_realloc(message, len + 5, 4);
			put_u32(message->body + pos, len);
			strcpy(message->body + pos + 4, str);
			break;
		case 'g':
			str = *va_arg(args, const char **);
			len = strlen(str);
			pos = body_realloc(message, len + 2, 1);
			put_u8(message->body + pos, len);
			strcpy(message->body + pos + 1, str);
			break;
		case 'b':
			uint32_val = *va_arg(args, bool *);
			pos = body_realloc(message, 4, 4);
			put_u32(message->body + pos, uint32_val);
			break;
		case 'y':
			uint8_val = *va_arg(args, uint8_t *);
			pos = body_realloc(message, 1, 1);
			put_u8(message->body + pos, uint8_val);
			break;
		case 'n':
			int16_val = *va_arg(args, int16_t *);
			pos = body_realloc(message, 2, 2);
			put_s16(message->body + pos, int16_val);
			break;
		case 'q':
			uint16_val = *va_arg(args, uint16_t *);
			pos = body_realloc(message, 2, 2);
			put_u16(message->body + pos, uint16_val);
			break;
		case 'i':
			int32_val = *va_arg(args, int32_t *);
			pos = body_realloc(message, 4, 4);
			put_s32(message->body + pos, int32_val);
			break;
		case 'u':
			uint32_val = *va_arg(args, uint32_t *);
			pos = body_realloc(message, 4, 4);
			put_u32(message->body + pos, uint32_val);
			break;
		case 'x':
			int64_val = *va_arg(args, int64_t *);
			pos = body_realloc(message, 8, 8);
			put_s64(message->body + pos, int64_val);
			break;
		case 't':
			uint64_val = *va_arg(args, uint64_t *);
			pos = body_realloc(message, 8, 8);
			put_u64(message->body + pos, uint64_val);
			break;
		case 'd':
			double_val = *va_arg(args, double *);
			pos = body_realloc(message, 8, 8);
			*((double *) (message->body + pos)) = double_val;
			break;
		case '(':
		case '{':
			pos = body_realloc(message, 0, 8);
			break;
		case ')':
		case '}':
			break;
		default:
			return false;
		}
	}

	hdr->body_length = message->body_size;

	return true;
}

LIB_EXPORT uint32_t l_dbus_method_call(struct l_dbus *dbus,
				const char *destination, const char *path,
				const char *interface, const char *method,
				l_dbus_message_func_t setup,
				l_dbus_message_func_t function,
				void *user_data, l_dbus_destroy_func_t destroy)
{
	struct l_dbus_message *message;

	if (unlikely(!dbus))
		return 0;

	message = l_dbus_message_new_method_call(destination, path,
							interface, method);

	if (setup)
		setup(message, user_data);

	return send_message(dbus, false, message, function, user_data, destroy);
}

LIB_EXPORT bool l_dbus_message_get_error(struct l_dbus_message *message,
					const char **name, const char **text)
{
	struct message_iter iter;
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

	message_iter_init(&iter, message, message->signature,
				message->body, message->body_size, 0);

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
	struct message_iter iter;
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

	message_iter_init(&iter, message, message->signature,
				message->body, message->body_size, 0);

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
	const char *path;

	if (unlikely(!message))
		return NULL;

	if (get_header_field(message, DBUS_MESSAGE_FIELD_PATH, &path))
		return path;

	return NULL;
}

LIB_EXPORT const char *l_dbus_message_get_interface(struct l_dbus_message *message)
{
	const char *interface;

	if (unlikely(!message))
		return NULL;

	if (get_header_field(message, DBUS_MESSAGE_FIELD_INTERFACE, &interface))
		return interface;

	return NULL;
}

LIB_EXPORT const char *l_dbus_message_get_member(struct l_dbus_message *message)
{
	const char *member;

	if (unlikely(!message))
		return NULL;

	if (get_header_field(message, DBUS_MESSAGE_FIELD_MEMBER, &member))
		return member;

	return NULL;
}

LIB_EXPORT const char *l_dbus_message_get_destination(struct l_dbus_message *message)
{
	const char *destination;

	if (unlikely(!message))
		return NULL;

	if (get_header_field(message, DBUS_MESSAGE_FIELD_DESTINATION,
							&destination))
		return destination;

	return NULL;
}

LIB_EXPORT const char *l_dbus_message_get_sender(struct l_dbus_message *message)
{
	const char *sender;

	if (unlikely(!message))
		return NULL;

	if (get_header_field(message, DBUS_MESSAGE_FIELD_SENDER, &sender))
		return sender;

	return NULL;
}

LIB_EXPORT const char *l_dbus_message_get_signature(
						struct l_dbus_message *message)
{
	const char *signature;

	if (unlikely(!message))
		return NULL;

	if (get_header_field(message, DBUS_MESSAGE_FIELD_SIGNATURE, &signature))
		return signature;

	return NULL;
}

LIB_EXPORT char l_dbus_message_iter_get_type(struct l_dbus_message_iter *iter)
{
	struct message_iter *real_iter;

	if (unlikely(!iter))
		return '\0';

	real_iter = (struct message_iter *) iter;

	if (!real_iter->signature)
		return '\0';

	return *real_iter->signature;
}

LIB_EXPORT bool l_dbus_message_iter_is_valid(struct l_dbus_message_iter *iter)
{
	struct message_iter *real_iter;

	if (unlikely(!iter))
		return false;

	real_iter = (struct message_iter *) iter;

	if (!real_iter->signature || *real_iter->signature == '\0')
		return false;

	return true;
}

LIB_EXPORT bool l_dbus_message_iter_next_entry(struct l_dbus_message_iter *iter,
									...)
{
	struct message_iter *real_iter;
	va_list args;
	bool result;

	if (unlikely(!iter))
		return false;

	real_iter = (struct message_iter *) iter;

	va_start(args, iter);
	result = message_iter_next_entry_valist(real_iter, args);
	va_end(args);

	return result;
}

LIB_EXPORT bool l_dbus_message_iter_get_variant(struct l_dbus_message_iter *iter,
						const char *signature, ...)
{
	struct message_iter *real_iter;
	va_list args;
	bool result;

	if (unlikely(!iter))
		return false;

	real_iter = (struct message_iter *) iter;

	if (!real_iter->signature || strcmp(real_iter->signature, signature))
		return false;

	va_start(args, signature);
	result = message_iter_next_entry_valist(real_iter, args);
	va_end(args);

	return result;
}
