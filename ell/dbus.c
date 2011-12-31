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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
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

#define DEFAULT_SYSTEM_BUS_ADDRESS "unix:path=/var/run/dbus/system_bus_socket"

#define DBUS_SERVICE_DBUS	"org.freedesktop.DBus"

#define DBUS_PATH_DBUS		"/org/freedesktop/DBus"

#define DBUS_INTERFACE_DBUS		"org.freedesktop.DBus"
#define DBUS_INTERFACE_INTROSPECTABLE	"org.freedesktop.DBus.Introspectable"
#define DBUS_INTERFACE_PROPERTIES	"org.freedesktop.DBus.Properties"

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
	uint32_t next_serial;
	struct l_queue *message_queue;
	struct l_hashmap *message_list;
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
	void *body;
	size_t body_size;
};

struct message_callback {
	uint32_t serial;
	struct l_dbus_message *message;
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

static void message_list_destroy(const void *key, void *value)
{
	message_queue_destroy(value);
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
	ptr[5] = 0x00;
	ptr[6] = 0x00;
	ptr[7] = 0x00;

	strcpy(data + 8, value);

	return 4 + 4 + len + 1;
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

	hdr->endian = 'l';
	hdr->message_type = 0x01;
	hdr->flags = 0x02;
	hdr->version = 0x01;
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
	if (unlikely(!message))
		return;

	if (__sync_sub_and_fetch(&message->refcount, 1))
		return;

	l_free(message->header);
	l_free(message->body);
	l_free(message);
}

static uint32_t get_reply_serial(struct l_dbus_message *message)
{
	struct dbus_header *hdr;
	unsigned char *ptr;
	unsigned int len;
	uint32_t reply_serial = 0;

	if (unlikely(!message || !message->header))
		return 0;

	hdr = message->header;

	ptr = message->header + DBUS_HEADER_SIZE;
	len = hdr->field_length;

	while (len > 0) {
		unsigned char type = ptr[0];
		unsigned char sig = ptr[2];
		unsigned int size = 0;

		switch (sig) {
		case 's':
			size = 4 + ptr[4] + 1;
			break;
		case 'u':
			if (type == 5)
				reply_serial = ptr[4];
			size = 8;
			break;
		}

		if (!size)
			break;

		ptr += align_len(size, 8);
		len -= align_len(size, 8);
	}

	return reply_serial;
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

	return true;
}

static struct l_dbus_message *receive_message_from_fd(int fd)
{
	struct l_dbus_message *message;
	struct dbus_header hdr;
	struct msghdr msg;
	struct iovec iov[2];
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

	len = recvmsg(fd, &msg, 0);
	if (len < 0)
		return NULL;

	return message;
}

static void message_read_handler(struct l_io *io, void *user_data)
{
	struct l_dbus *dbus = user_data;
	struct l_dbus_message *message;
	struct message_callback *callback;
	uint32_t reply_serial;
	int fd;

	fd = l_io_get_fd(io);

	message = receive_message_from_fd(fd);
	if (!message)
		return;

	l_util_hexdump_two(true, message->header, message->header_size,
					message->body, message->body_size,
					dbus->debug_handler, dbus->debug_data);

	reply_serial = get_reply_serial(message);
	if (!reply_serial)
		goto done;

	callback = l_hashmap_remove(dbus->message_list,
					L_UINT_TO_PTR(reply_serial));
	if (!callback)
		goto done;

	if (callback->callback)
		callback->callback(message, callback->user_data);

	if (callback->destroy)
		callback->destroy(callback->user_data);

	message_queue_destroy(callback);

done:
	l_dbus_message_unref(message);
}

static uint32_t send_message(struct l_dbus *dbus,
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

	l_queue_push_tail(dbus->message_queue, callback);

	l_io_set_write_handler(dbus->io, message_write_handler, dbus, NULL);

	return callback->serial;
}

static void hello_callback(struct l_dbus_message *message, void *user_data)
{
	struct l_dbus *dbus = user_data;

	dbus->is_ready = true;

	if (dbus->ready_handler)
		dbus->ready_handler(dbus->ready_data);
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

		send_message(dbus, message, hello_callback, dbus, NULL);

		l_dbus_message_unref(message);

		return true;
	}

	return false;
}

static void auth_read_handler(struct l_io *io, void *user_data)
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
		return;

	end = strstr(ptr, "\r\n");
	if (!end)
		return;

	if (end - ptr + 2 != len)
		return;

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
	dbus->next_serial = 1;

	dbus->message_queue = l_queue_new();
	dbus->message_list = l_hashmap_new();

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

	if (unlikely(!dbus->is_ready))
		return 0;

	return send_message(dbus, message, function, user_data, destroy);
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