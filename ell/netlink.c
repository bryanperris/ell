/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2011  Intel Corporation. All rights reserved.
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

#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#include "util.h"
#include "hashmap.h"
#include "queue.h"
#include "io.h"
#include "netlink.h"
#include "private.h"

struct command {
	unsigned int id;
	uint32_t seq;
	uint32_t len;
	l_netlink_command_func_t handler;
	l_netlink_destroy_func_t destroy;
	void *user_data;
};

struct notify {
	uint32_t group;
	l_netlink_notify_func_t handler;
	l_netlink_destroy_func_t destroy;
	void *user_data;
};

struct l_netlink {
	uint32_t pid;
	struct l_io *io;
	uint32_t next_seq;
	struct l_queue *command_queue;
	struct l_hashmap *command_pending;
	struct l_hashmap *command_lookup;
	unsigned int next_command_id;
	struct l_hashmap *notify_groups;
	struct l_hashmap *notify_lookup;
	unsigned int next_notify_id;
	l_netlink_debug_func_t debug_handler;
	l_netlink_destroy_func_t debug_destroy;
	void *debug_data;
};

static void destroy_command(const void *key, void *data)
{
	struct command *command = data;

	if (command->destroy)
		command->destroy(command->user_data);

	l_free(command);
}

static void destroy_notify(const void *key, void *data)
{
	struct notify *notify = data;

	if (notify->destroy)
		notify->destroy(notify->user_data);

	l_free(notify);
}

static void destroy_notify_group(const void *key, void *data)
{
	struct l_hashmap *notify_list = data;

	l_hashmap_destroy(notify_list, destroy_notify);
}

static bool can_write_data(struct l_io *io, void *user_data)
{
	struct l_netlink *netlink = user_data;
	struct command *command;
	struct sockaddr_nl addr;
	const void *data;
	ssize_t written;
	int sk;

	command = l_queue_pop_head(netlink->command_queue);
	if (!command)
		return false;

	sk = l_io_get_fd(io);

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;

	data = ((void *) command) + NLMSG_ALIGN(sizeof(struct command));

	written = sendto(sk, data, command->len, 0,
				(struct sockaddr *) &addr, sizeof(addr));
	if (written != command->len) {
		l_hashmap_remove(netlink->command_lookup,
					L_UINT_TO_PTR(command->id));
		destroy_command(NULL, command);
		return true;
	}

	l_util_hexdump(false, data, command->len,
				netlink->debug_handler, netlink->debug_data);

	l_hashmap_insert(netlink->command_pending,
				L_UINT_TO_PTR(command->seq), command);

	return l_queue_length(netlink->command_queue) > 0;
}

static void do_notify(const void *key, void *value, void *user_data)
{
	struct nlmsghdr *nlmsg = user_data;
	struct notify *notify = value;

	if (notify->handler) {
		notify->handler(nlmsg->nlmsg_type, NLMSG_DATA(nlmsg),
			nlmsg->nlmsg_len - NLMSG_HDRLEN, notify->user_data);
	}
}

static void process_broadcast(struct l_netlink *netlink, uint32_t group,
						struct nlmsghdr *nlmsg)
{
	struct l_hashmap *notify_list;

	notify_list = l_hashmap_lookup(netlink->notify_groups,
						L_UINT_TO_PTR(group));
	if (!notify_list)
		return;

	l_hashmap_foreach(notify_list, do_notify, nlmsg);
}

static void process_message(struct l_netlink *netlink, struct nlmsghdr *nlmsg)
{
	const void *data = nlmsg;
	struct command *command;

	command = l_hashmap_remove(netlink->command_pending,
					L_UINT_TO_PTR(nlmsg->nlmsg_seq));
	if (!command)
		return;

	if (!command->handler)
		goto done;

	if (nlmsg->nlmsg_type < NLMSG_MIN_TYPE) {
		const struct nlmsgerr *err;

		switch (nlmsg->nlmsg_type) {
		case NLMSG_ERROR:
			err = data + NLMSG_HDRLEN;

			command->handler(-err->error, 0, NULL, 0,
							command->user_data);
			break;
		}
	} else {
		command->handler(0, nlmsg->nlmsg_type, data + NLMSG_HDRLEN,
					nlmsg->nlmsg_len - NLMSG_HDRLEN,
					command->user_data);
	}

done:
	l_hashmap_remove(netlink->command_lookup, L_UINT_TO_PTR(command->id));

	destroy_command(NULL, command);
}

static void process_multi(struct l_netlink *netlink, struct nlmsghdr *nlmsg)
{
	const void *data = nlmsg;
	struct command *command;

	if (nlmsg->nlmsg_type < NLMSG_MIN_TYPE) {
		command = l_hashmap_remove(netlink->command_pending,
					L_UINT_TO_PTR(nlmsg->nlmsg_seq));
		if (!command)
			return;

		l_hashmap_remove(netlink->command_lookup,
					L_UINT_TO_PTR(command->id));

		destroy_command(NULL, command);
	} else {
		command = l_hashmap_lookup(netlink->command_pending,
					L_UINT_TO_PTR(nlmsg->nlmsg_seq));
		if (!command)
			return;

		if (!command->handler)
			return;

		command->handler(0, nlmsg->nlmsg_type, data + NLMSG_HDRLEN,
					nlmsg->nlmsg_len - NLMSG_HDRLEN,
					command->user_data);
	}
}

static void can_read_data(struct l_io *io, void *user_data)
{
	struct l_netlink *netlink = user_data;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	struct nlmsghdr *nlmsg;
	unsigned char buffer[4096];
	unsigned char control[32];
	uint32_t group = 0;
	ssize_t len;
	int sk;

	sk = l_io_get_fd(io);

	iov.iov_base = buffer;
	iov.iov_len = sizeof(buffer);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	len = recvmsg(sk, &msg, 0);
	if (len < 0)
		return;

	l_util_hexdump(true, buffer, len, netlink->debug_handler,
						netlink->debug_data);

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
					cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		struct nl_pktinfo *pktinfo;

		if (cmsg->cmsg_level != SOL_NETLINK)
			continue;

		if (cmsg->cmsg_type != NETLINK_PKTINFO)
			continue;

		pktinfo = (void *) CMSG_DATA(cmsg);

		group = pktinfo->group;
	}

	for (nlmsg = iov.iov_base; NLMSG_OK(nlmsg, len);
					nlmsg = NLMSG_NEXT(nlmsg, len)) {
		if (group > 0 && nlmsg->nlmsg_seq == 0) {
			process_broadcast(netlink, group, nlmsg);
			continue;
		}

		if (nlmsg->nlmsg_pid != netlink->pid)
			continue;

		if (nlmsg->nlmsg_flags & NLM_F_MULTI)
			process_multi(netlink, nlmsg);
		else
			process_message(netlink, nlmsg);
	}
}

static int create_netlink_socket(int protocol, uint32_t *pid)
{
	struct sockaddr_nl addr;
	socklen_t addrlen = sizeof(addr);
	int sk, pktinfo = 1;

	sk = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
								protocol);
	if (sk < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(sk);
		return -1;
	}

	if (getsockname(sk, (struct sockaddr *) &addr, &addrlen) < 0) {
		close(sk);
		return -1;
	}

	if (setsockopt(sk, SOL_NETLINK, NETLINK_PKTINFO,
					&pktinfo, sizeof(pktinfo)) < 0) {
		close(sk);
		return -1;
	}

	if (pid)
		*pid = addr.nl_pid;

	return sk;
}

LIB_EXPORT struct l_netlink *l_netlink_new(int protocol)
{
	struct l_netlink *netlink;
	int sk;

	netlink = l_new(struct l_netlink, 1);

	netlink->next_seq = 1;
	netlink->next_command_id = 1;
	netlink->next_notify_id = 1;

	sk = create_netlink_socket(protocol, &netlink->pid);
	if (sk < 0) {
		l_free(netlink);
		return NULL;
	}

	netlink->io = l_io_new(sk);
	if (!netlink->io) {
		close(sk);
		l_free(netlink);
		return NULL;
	}

	l_io_set_close_on_destroy(netlink->io, true);

	l_io_set_read_handler(netlink->io, can_read_data, netlink, NULL);

	netlink->command_queue = l_queue_new();
	netlink->command_pending = l_hashmap_new();
	netlink->command_lookup = l_hashmap_new();

	netlink->notify_groups = l_hashmap_new();
	netlink->notify_lookup = l_hashmap_new();

	return netlink;
}

LIB_EXPORT void l_netlink_destroy(struct l_netlink *netlink)
{
	if (unlikely(!netlink))
		return;

	l_hashmap_destroy(netlink->notify_lookup, NULL);
	l_hashmap_destroy(netlink->notify_groups, destroy_notify_group);

	l_queue_destroy(netlink->command_queue, NULL);
	l_hashmap_destroy(netlink->command_pending, NULL);
	l_hashmap_destroy(netlink->command_lookup, destroy_command);

	l_io_destroy(netlink->io);

	l_free(netlink);
}

LIB_EXPORT unsigned int l_netlink_send(struct l_netlink *netlink,
			uint16_t type, uint16_t flags, const void *data,
			uint32_t len, l_netlink_command_func_t function,
			void *user_data, l_netlink_destroy_func_t destroy)
{
	struct command *command;
	struct nlmsghdr *nlmsg;
	size_t size;

	if (unlikely(!netlink))
		return 0;

	if (!netlink->command_queue || !netlink->command_pending ||
						!netlink->command_lookup)
		return 0;

	if (flags & 0xff)
		return 0;

	size = NLMSG_ALIGN(sizeof(struct command)) +
					NLMSG_HDRLEN + NLMSG_ALIGN(len);

	command = l_malloc(size);

	memset(command, 0, size);
	command->handler = function;
	command->destroy = destroy;
	command->user_data = user_data;

	command->id = netlink->next_command_id;

	if (!l_hashmap_insert(netlink->command_lookup,
					L_UINT_TO_PTR(command->id), command))
		goto free_command;

	command->seq = netlink->next_seq++;
	command->len = NLMSG_HDRLEN + NLMSG_ALIGN(len);

	nlmsg = ((void *) command) + NLMSG_ALIGN(sizeof(struct command));

	nlmsg->nlmsg_len = command->len;
	nlmsg->nlmsg_type = type;
	nlmsg->nlmsg_flags = NLM_F_REQUEST | flags;
	nlmsg->nlmsg_seq = command->seq;
	nlmsg->nlmsg_pid = netlink->pid;

	if (data && len > 0)
		memcpy(((void *) nlmsg) + NLMSG_HDRLEN, data, len);

	l_queue_push_tail(netlink->command_queue, command);

	l_io_set_write_handler(netlink->io, can_write_data, netlink, NULL);

	netlink->next_command_id++;

	return command->id;

free_command:
	l_free(command);

	return 0;
}

LIB_EXPORT bool l_netlink_cancel(struct l_netlink *netlink, unsigned int id)
{
	struct command *command;

	if (unlikely(!netlink || !id))
		return false;

	if (!netlink->command_queue || !netlink->command_pending ||
						!netlink->command_lookup)
		return false;

	command = l_hashmap_remove(netlink->command_lookup, L_UINT_TO_PTR(id));
	if (!command)
		return false;

	if (!l_queue_remove(netlink->command_queue, command)) {
		l_hashmap_remove(netlink->command_pending,
					L_UINT_TO_PTR(command->seq));
	}

	destroy_command(NULL, command);

	return true;
}

static bool add_membership(struct l_netlink *netlink, uint32_t group)
{
	int sk, value = group;

	sk = l_io_get_fd(netlink->io);

	if (setsockopt(sk, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
						&value, sizeof(value)) < 0)
		return false;

	return true;
}

static bool drop_membership(struct l_netlink *netlink, uint32_t group)
{
	int sk, value = group;

	sk = l_io_get_fd(netlink->io);

	if (setsockopt(sk, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP,
						&value, sizeof(value)) < 0)
		return false;

	return true;
}

LIB_EXPORT unsigned int l_netlink_register(struct l_netlink *netlink,
			uint32_t group, l_netlink_notify_func_t function,
			void *user_data, l_netlink_destroy_func_t destroy)
{
	struct l_hashmap *notify_list;
	struct notify *notify;
	unsigned int id;

	if (unlikely(!netlink))
		return 0;

	if (!netlink->notify_groups || !netlink->notify_lookup)
		return 0;

	notify_list = l_hashmap_lookup(netlink->notify_groups,
						L_UINT_TO_PTR(group));
	if (!notify_list) {
		notify_list = l_hashmap_new();
		if (!notify_list)
			return 0;

		if (!l_hashmap_insert(netlink->notify_groups,
					L_UINT_TO_PTR(group), notify_list)) {
			l_hashmap_destroy(notify_list, NULL);
			return 0;
		}
	}

	notify = l_new(struct notify, 1);

	notify->group = group;
	notify->handler = function;
	notify->destroy = destroy;
	notify->user_data = user_data;

	id = netlink->next_notify_id;

	if (!l_hashmap_insert(netlink->notify_lookup,
					L_UINT_TO_PTR(id), notify_list))
		goto free_notify;

	if (!l_hashmap_insert(notify_list, L_UINT_TO_PTR(id), notify))
		goto remove_lookup;

	if (l_hashmap_size(notify_list) == 1) {
		if (!add_membership(netlink, notify->group))
			goto remove_notify;
	}

	netlink->next_notify_id++;

	return id;

remove_notify:
	l_hashmap_remove(notify_list, L_UINT_TO_PTR(id));

remove_lookup:
	l_hashmap_remove(netlink->notify_lookup, L_UINT_TO_PTR(id));

free_notify:
	l_free(notify);

	return 0;
}

LIB_EXPORT bool l_netlink_unregister(struct l_netlink *netlink, unsigned int id)
{
	struct l_hashmap *notify_list;
	struct notify *notify;

	if (unlikely(!netlink || !id))
		return false;

	if (!netlink->notify_groups || !netlink->notify_lookup)
		return false;

	notify_list = l_hashmap_remove(netlink->notify_lookup,
						L_UINT_TO_PTR(id));
	if (!notify_list)
		return false;

	notify = l_hashmap_remove(notify_list, L_UINT_TO_PTR(id));
	if (!notify)
		return false;

	if (l_hashmap_size(notify_list) == 0)
		drop_membership(netlink, notify->group);

	destroy_notify(NULL, notify);

	return true;
}

LIB_EXPORT bool l_netlink_set_debug(struct l_netlink *netlink,
			l_netlink_debug_func_t function,
			void *user_data, l_netlink_destroy_func_t destroy)
{
	if (unlikely(!netlink))
		return false;

	if (netlink->debug_destroy)
		netlink->debug_destroy(netlink->debug_data);

	netlink->debug_handler = function;
	netlink->debug_destroy = destroy;
	netlink->debug_data = user_data;

	//l_io_set_debug(netlink->io, function, user_data, NULL);

	return true;
}
