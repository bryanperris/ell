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

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/genetlink.h>

#include "util.h"
#include "queue.h"
#include "io.h"
#include "netlink-private.h"
#include "genl.h"
#include "genl-private.h"
#include "private.h"

#define MAX_NESTING_LEVEL 4

struct genl_unicast_notify {
	l_genl_msg_func_t handler;
	l_genl_destroy_func_t destroy;
	void *user_data;
};

struct l_genl {
	int ref_count;
	int fd;
	bool close_on_unref;
	uint32_t pid;
	uint32_t next_seq;
	struct l_io *io;
	bool writer_active;
	struct l_queue *request_queue;
	struct l_queue *pending_list;
	struct l_queue *notify_list;
	unsigned int next_request_id;
	unsigned int next_notify_id;
	struct l_queue *family_list;
	struct l_genl_family *nlctrl;
	struct genl_unicast_notify *unicast_notify;
	l_genl_debug_func_t debug_callback;
	l_genl_destroy_func_t debug_destroy;
	void *debug_data;
};

struct l_genl_msg {
	int ref_count;
	int error;
	uint8_t cmd;
	uint8_t version;
	void *data;
	uint32_t size;
	uint32_t len;
	struct nlattr *nests[MAX_NESTING_LEVEL];
	uint8_t nesting_level;
};

struct genl_request {
	unsigned int id;
	uint16_t type;
	uint16_t flags;
	uint32_t seq;
	struct l_genl_msg *msg;
	l_genl_msg_func_t callback;
	l_genl_destroy_func_t destroy;
	void *user_data;
};

struct genl_mcast_notify {
	unsigned int id;
	uint16_t type;
	uint32_t group;
	l_genl_msg_func_t callback;
	l_genl_destroy_func_t destroy;
	void *user_data;
};

struct genl_op {
	uint32_t id;
	uint32_t flags;
};

struct genl_mcast {
	char name[GENL_NAMSIZ];
	uint32_t id;
	unsigned int users;
};

struct l_genl_family {
	int ref_count;
	struct l_genl *genl;
	char name[GENL_NAMSIZ];
	uint16_t id;
	uint32_t version;
	uint32_t hdrsize;
	uint32_t maxattr;
	struct l_queue *op_list;
	struct l_queue *mcast_list;
	l_genl_watch_func_t watch_appeared;
	l_genl_watch_func_t watch_vanished;
	l_genl_destroy_func_t watch_destroy;
	void *watch_data;
	unsigned int nlctrl_cmd;
};

static void destroy_request(void *data)
{
	struct genl_request *request = data;

	if (request->destroy)
		request->destroy(request->user_data);

	l_genl_msg_unref(request->msg);

	l_free(request);
}

static void destroy_notify(void *data)
{
	struct genl_mcast_notify *notify = data;

	if (notify->destroy)
		notify->destroy(notify->user_data);

	l_free(notify);
}

static struct l_genl_family *family_alloc(struct l_genl *genl,
							const char *name)
{
	struct l_genl_family *family;

	family = l_new(struct l_genl_family, 1);

	family->genl = genl;
	strncpy(family->name, name, GENL_NAMSIZ);

	family->op_list = l_queue_new();
	family->mcast_list = l_queue_new();

	return l_genl_family_ref(family);
}

static void op_free(void *data)
{
	struct genl_op *op = data;

	l_free(op);
}

static void mcast_free(void *data, void *user_data)
{
	struct l_genl *genl= user_data;
	struct genl_mcast *mcast = data;

	if (genl && mcast->users > 0) {
		int group = mcast->id;

		setsockopt(genl->fd, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP,
							&group, sizeof(group));
	}

	l_free(mcast);
}

static void family_free(void *data)
{
	struct l_genl_family *family = data;

	family->genl = NULL;

	l_genl_family_unref(family);
}

static void family_add_op(struct l_genl_family *family, uint32_t id,
							uint32_t flags)
{
	struct genl_op *op;

	op = l_new(struct genl_op, 1);

	op->id = id;
	op->flags = flags;

	l_queue_push_tail(family->op_list, op);
}

static bool match_mcast_name(const void *a, const void *b)
{
	const struct genl_mcast *mcast = a;
	const char *name = b;

	return !strcmp(mcast->name, name);
}

static void family_add_mcast(struct l_genl_family *family, const char *name,
								uint32_t id)
{
	struct l_genl *genl = family->genl;
	struct genl_mcast *mcast;

	if (!genl)
		return;

	mcast = l_queue_find(family->mcast_list, match_mcast_name,
							(char *) name);
	if (mcast)
		return;

	mcast = l_new(struct genl_mcast, 1);

	strncpy(mcast->name, name, GENL_NAMSIZ);
	mcast->id = id;
	mcast->users = 0;

	l_queue_push_tail(family->mcast_list, mcast);
}

static struct l_genl_msg *msg_alloc(uint8_t cmd, uint8_t version, uint32_t size)
{
	struct l_genl_msg *msg;

	msg = l_new(struct l_genl_msg, 1);

	msg->cmd = cmd;
	msg->version = version;

	msg->len = NLMSG_HDRLEN + GENL_HDRLEN;
	msg->size = msg->len + NLMSG_ALIGN(size);

	msg->data = l_new(unsigned char, msg->size);
	msg->nesting_level = 0;

	return l_genl_msg_ref(msg);
}

struct l_genl_msg *_genl_msg_create(const struct nlmsghdr *nlmsg)
{
	struct l_genl_msg *msg;

	msg = l_new(struct l_genl_msg, 1);

	if (nlmsg->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = NLMSG_DATA(nlmsg);

		msg->error = err->error;
		goto done;
	}

	msg->data = l_memdup(nlmsg, nlmsg->nlmsg_len);

	msg->len = nlmsg->nlmsg_len;
	msg->size = nlmsg->nlmsg_len;

	if (msg->len >= GENL_HDRLEN) {
		struct genlmsghdr *genlmsg = msg->data + NLMSG_HDRLEN;

		msg->cmd = genlmsg->cmd;
		msg->version = genlmsg->version;
	}

done:
	return l_genl_msg_ref(msg);
}

static void write_watch_destroy(void *user_data)
{
	struct l_genl *genl = user_data;

	genl->writer_active = false;
}

static bool can_write_data(struct l_io *io, void *user_data)
{
	struct l_genl *genl = user_data;
	struct genl_request *request;
	struct nlmsghdr *nlmsg;
	struct genlmsghdr *genlmsg;
	ssize_t bytes_written;

	request = l_queue_pop_head(genl->request_queue);
	if (!request)
		return false;

	if (genl->next_seq < 1)
		genl->next_seq = 1;

	request->seq = genl->next_seq++;

	nlmsg = request->msg->data;

	nlmsg->nlmsg_len = request->msg->len;
	nlmsg->nlmsg_type = request->type;
	nlmsg->nlmsg_flags = request->flags;
	nlmsg->nlmsg_seq = request->seq;
	nlmsg->nlmsg_pid = genl->pid;

	genlmsg = request->msg->data + NLMSG_HDRLEN;

	genlmsg->cmd = request->msg->cmd;
	genlmsg->version = request->msg->version;

	bytes_written = send(genl->fd, request->msg->data,
						request->msg->len, 0);
	if (bytes_written < 0) {
		l_queue_push_head(genl->request_queue, request);
		return false;
	}

	l_util_hexdump(false, request->msg->data, bytes_written,
				genl->debug_callback, genl->debug_data);

	l_queue_push_tail(genl->pending_list, request);

	return false;
}

static void wakeup_writer(struct l_genl *genl)
{
	if (genl->writer_active)
		return;

	if (l_queue_isempty(genl->request_queue))
		return;

	if (!l_queue_isempty(genl->pending_list))
		return;

	l_io_set_write_handler(genl->io, can_write_data, genl,
						write_watch_destroy);

	genl->writer_active = true;
}

static bool match_request_seq(const void *a, const void *b)
{
	const struct genl_request *request = a;
	uint32_t seq = L_PTR_TO_UINT(b);

	return request->seq == seq;
}

static void process_unicast(struct l_genl *genl, const struct nlmsghdr *nlmsg)
{
	struct l_genl_msg *msg;
	struct genl_request *request;
	struct genl_unicast_notify *notify;

	if (nlmsg->nlmsg_type == NLMSG_NOOP ||
					nlmsg->nlmsg_type == NLMSG_OVERRUN)
		return;

	request = l_queue_remove_if(genl->pending_list, match_request_seq,
					L_UINT_TO_PTR(nlmsg->nlmsg_seq));

	msg = _genl_msg_create(nlmsg);
	if (!msg) {
		if (request) {
			destroy_request(request);
			wakeup_writer(genl);
		}
		return;
	}

	if (request) {
		if (request->callback && nlmsg->nlmsg_type != NLMSG_DONE)
			request->callback(msg, request->user_data);

		if (nlmsg->nlmsg_flags & NLM_F_MULTI) {
			if (nlmsg->nlmsg_type == NLMSG_DONE) {
				destroy_request(request);
				wakeup_writer(genl);
			} else
				l_queue_push_head(genl->pending_list, request);
		} else {
			destroy_request(request);
			wakeup_writer(genl);
		}
	} else {
		notify = genl->unicast_notify;
		if (notify && notify->handler)
			notify->handler(msg, notify->user_data);
	}

	l_genl_msg_unref(msg);
}

struct notify_type_group {
	struct l_genl_msg *msg;
	uint16_t type;
	uint32_t group;
};

static void notify_handler(void *data, void *user_data)
{
	struct genl_mcast_notify *notify = data;
	struct notify_type_group *match = user_data;

	if (notify->type != match->type)
		return;

	if (notify->group != match->group)
		return;

	if (notify->callback)
		notify->callback(match->msg, notify->user_data);
}

static void process_multicast(struct l_genl *genl, uint32_t group,
						const struct nlmsghdr *nlmsg)
{
	struct notify_type_group match;

	match.msg = _genl_msg_create(nlmsg);
	if (!match.msg)
		return;

	match.type = nlmsg->nlmsg_type;
	match.group = group;

	l_queue_foreach(genl->notify_list, notify_handler, &match);

	l_genl_msg_unref(match.msg);
}

static void read_watch_destroy(void *user_data)
{
}

static bool received_data(struct l_io *io, void *user_data)
{
	struct l_genl *genl = user_data;
	struct cmsghdr *cmsg;
	struct msghdr msg;
	struct iovec iov;
	unsigned char buf[8192];
	unsigned char control[32];
	ssize_t bytes_read;
	struct nlmsghdr *nlmsg;
	uint32_t group = 0;

	memset(&iov, 0, sizeof(iov));
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	bytes_read = recvmsg(genl->fd, &msg, 0);
	if (bytes_read < 0) {
		if (errno != EAGAIN && errno != EINTR)
			return false;

		return true;
	}

	l_util_hexdump(true, buf, bytes_read,
				genl->debug_callback, genl->debug_data);

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
					cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		struct nl_pktinfo pktinfo;

		if (cmsg->cmsg_level != SOL_NETLINK)
			continue;

		if (cmsg->cmsg_type != NETLINK_PKTINFO)
			continue;

		memcpy(&pktinfo, CMSG_DATA(cmsg), sizeof(pktinfo));

		group = pktinfo.group;
	}

	for (nlmsg = iov.iov_base; NLMSG_OK(nlmsg, bytes_read);
				nlmsg = NLMSG_NEXT(nlmsg, bytes_read)) {
		if (group > 0)
			process_multicast(genl, group, nlmsg);
		else
			process_unicast(genl, nlmsg);
	}

	return true;
}

LIB_EXPORT struct l_genl *l_genl_new(int fd)
{
	struct l_genl *genl;

	if (unlikely(fd < 0))
		return NULL;

	genl = l_new(struct l_genl, 1);

	genl->fd = fd;
	genl->close_on_unref = false;

	genl->nlctrl = family_alloc(genl, "nlctrl");

	genl->nlctrl->id = GENL_ID_CTRL;

	family_add_mcast(genl->nlctrl, "notify", GENL_ID_CTRL);

	l_queue_push_tail(genl->family_list, genl->nlctrl);

	genl->io = l_io_new(genl->fd);

	genl->request_queue = l_queue_new();
	genl->pending_list = l_queue_new();
	genl->notify_list = l_queue_new();
	genl->family_list = l_queue_new();

	l_io_set_read_handler(genl->io, received_data, genl,
						read_watch_destroy);

	return l_genl_ref(genl);
}

LIB_EXPORT struct l_genl *l_genl_new_default(void)
{
	struct l_genl *genl;
	struct sockaddr_nl addr;
	socklen_t addrlen = sizeof(addr);
	int fd, pktinfo = 1;

	fd = socket(PF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
							NETLINK_GENERIC);
	if (fd < 0)
		return NULL;

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = 0;

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(fd);
		return NULL;
	}

	genl = l_genl_new(fd);

	genl->close_on_unref = true;

	if (getsockname(fd, (struct sockaddr *) &addr, &addrlen) < 0) {
		l_genl_unref(genl);
		return NULL;
	}

	genl->pid = addr.nl_pid;

	if (setsockopt(fd, SOL_NETLINK, NETLINK_PKTINFO,
					&pktinfo, sizeof(pktinfo)) < 0) {
		l_genl_unref(genl);
		return NULL;
	}

	return genl;
}

LIB_EXPORT struct l_genl *l_genl_ref(struct l_genl *genl)
{
	if (unlikely(!genl))
		return NULL;

	__sync_fetch_and_add(&genl->ref_count, 1);

	return genl;
}

LIB_EXPORT void l_genl_unref(struct l_genl *genl)
{
	if (unlikely(!genl))
		return;

	if (__sync_sub_and_fetch(&genl->ref_count, 1))
		return;

	l_queue_destroy(genl->notify_list, destroy_notify);
	l_queue_destroy(genl->pending_list, destroy_request);
	l_queue_destroy(genl->request_queue, destroy_request);

	l_io_set_write_handler(genl->io, NULL, NULL, NULL);
	l_io_set_read_handler(genl->io, NULL, NULL, NULL);

	l_io_destroy(genl->io);
	genl->io = NULL;

	l_genl_family_unref(genl->nlctrl);

	l_queue_destroy(genl->family_list, family_free);

	if (genl->close_on_unref)
		close(genl->fd);

	if (genl->debug_destroy)
		genl->debug_destroy(genl->debug_data);

	l_genl_set_unicast_handler(genl, NULL, NULL, NULL);

	l_free(genl);
}

LIB_EXPORT bool l_genl_set_debug(struct l_genl *genl,
					l_genl_debug_func_t callback,
					void *user_data,
					l_genl_destroy_func_t destroy)
{
	if (unlikely(!genl))
		return false;

	if (genl->debug_destroy)
		genl->debug_destroy(genl->debug_data);

	genl->debug_callback = callback;
	genl->debug_destroy = destroy;
	genl->debug_data = user_data;

	return true;
}

LIB_EXPORT bool l_genl_set_close_on_unref(struct l_genl *genl, bool do_close)
{
	if (unlikely(!genl))
		return false;

	genl->close_on_unref = do_close;

	return true;
}

LIB_EXPORT bool l_genl_set_unicast_handler(struct l_genl *genl,
						l_genl_msg_func_t handler,
						void *user_data,
						l_genl_destroy_func_t destroy)
{
	struct genl_unicast_notify *notify;

	if (!genl)
		return false;

	notify = genl->unicast_notify;
	if (notify) {
		if (notify->destroy)
			notify->destroy(notify->user_data);

		if (!handler) {
			l_free(notify);
			genl->unicast_notify = NULL;
			return true;
		}
	} else {
		if (!handler)
			return false;

		notify = l_new(struct genl_unicast_notify, 1);
		genl->unicast_notify = notify;
	}

	notify->handler = handler;
	notify->destroy = destroy;
	notify->user_data = user_data;

	return true;
}

const void *_genl_msg_as_bytes(struct l_genl_msg *msg, uint16_t type,
					uint16_t flags, uint32_t seq,
					uint32_t pid,
					size_t *out_size)
{
	struct nlmsghdr *nlmsg;
	struct genlmsghdr *genlmsg;

	nlmsg = msg->data;

	nlmsg->nlmsg_len = msg->len;
	nlmsg->nlmsg_type = type;
	nlmsg->nlmsg_flags = flags;
	nlmsg->nlmsg_seq = seq;
	nlmsg->nlmsg_pid = pid;

	genlmsg = msg->data + NLMSG_HDRLEN;

	genlmsg->cmd = msg->cmd;
	genlmsg->version = msg->version;

	if (out_size)
		*out_size = msg->len;

	return msg->data;
}

LIB_EXPORT struct l_genl_msg *l_genl_msg_new(uint8_t cmd)
{
	return l_genl_msg_new_sized(cmd, 0);
}

LIB_EXPORT struct l_genl_msg *l_genl_msg_new_sized(uint8_t cmd, uint32_t size)
{
	return msg_alloc(cmd, 0x00, size);
}

LIB_EXPORT struct l_genl_msg *l_genl_msg_ref(struct l_genl_msg *msg)
{
	if (unlikely(!msg))
		return NULL;

	__sync_fetch_and_add(&msg->ref_count, 1);

	return msg;
}

LIB_EXPORT void l_genl_msg_unref(struct l_genl_msg *msg)
{
	if (unlikely(!msg))
		return;

	if (__sync_sub_and_fetch(&msg->ref_count, 1))
		return;

	l_free(msg->data);
	l_free(msg);
}

LIB_EXPORT uint8_t l_genl_msg_get_command(struct l_genl_msg *msg)
{
	if (unlikely(!msg))
		return 0;

	return msg->cmd;
}

LIB_EXPORT uint8_t l_genl_msg_get_version(struct l_genl_msg *msg)
{
	if (unlikely(!msg))
		return 0;

	return msg->version;
}

LIB_EXPORT int l_genl_msg_get_error(struct l_genl_msg *msg)
{
	if (unlikely(!msg))
		return -ENOMSG;

	return msg->error;
}

LIB_EXPORT bool l_genl_msg_append_attr(struct l_genl_msg *msg, uint16_t type,
						uint16_t len, const void *data)
{
	struct nlattr *nla;

	if (unlikely(!msg))
		return false;

	if (msg->len + NLA_HDRLEN + NLA_ALIGN(len) > msg->size)
		return false;

	nla = msg->data + msg->len;
	nla->nla_len = NLA_HDRLEN + len;
	nla->nla_type = type;

	memcpy(msg->data + msg->len + NLA_HDRLEN, data, len);
	msg->len += NLA_HDRLEN + NLA_ALIGN(len);

	return true;
}

LIB_EXPORT bool l_genl_msg_append_attrv(struct l_genl_msg *msg, uint16_t type,
					struct iovec *iov, size_t iov_len)
{
	struct nlattr *nla;
	size_t len = 0;
	unsigned int i;

	if (unlikely(!msg))
		return false;

	for (i = 0; i < iov_len; i++)
		len += iov[i].iov_len;

	if (msg->len + NLA_HDRLEN + NLA_ALIGN(len) > msg->size)
		return false;

	nla = msg->data + msg->len;
	nla->nla_len = NLA_HDRLEN + len;
	nla->nla_type = type;

	msg->len += NLA_HDRLEN;

	for (i = 0; i < iov_len; i++, iov++) {
		memcpy(msg->data + msg->len, iov->iov_base, iov->iov_len);
		msg->len += iov->iov_len;
	}

	msg->len += NLA_ALIGN(len) - len;

	return true;
}

LIB_EXPORT bool l_genl_msg_enter_nested(struct l_genl_msg *msg, uint16_t type)
{
	struct nlattr *nla;

	if (unlikely(!msg))
		return false;

	if (unlikely(msg->nesting_level == MAX_NESTING_LEVEL))
		return false;

	if (msg->len + NLA_HDRLEN > msg->size)
		return false;

	nla = msg->data + msg->len;
	nla->nla_type = type;
	nla->nla_len = msg->len; /* Save position */

	msg->nests[msg->nesting_level] = nla;
	msg->nesting_level += 1;

	msg->len += NLA_HDRLEN;

	return true;
}

LIB_EXPORT bool l_genl_msg_leave_nested(struct l_genl_msg *msg)
{
	struct nlattr *nla;

	if (unlikely(!msg))
		return false;

	if (unlikely(msg->nesting_level == 0))
		return false;

	nla = msg->nests[msg->nesting_level - 1];
	nla->nla_len = msg->len - nla->nla_len;

	msg->nesting_level -= 1;

	return true;
}

#define NLA_OK(nla,len)         ((len) >= (int) sizeof(struct nlattr) && \
				(nla)->nla_len >= sizeof(struct nlattr) && \
				(nla)->nla_len <= (len))
#define NLA_NEXT(nla,attrlen)	((attrlen) -= NLMSG_ALIGN((nla)->nla_len), \
				(struct nlattr*)(((char*)(nla)) + \
				NLMSG_ALIGN((nla)->nla_len)))

#define NLA_LENGTH(len)		(NLMSG_ALIGN(sizeof(struct nlattr)) + (len))
#define NLA_DATA(nla)		((void*)(((char*)(nla)) + NLA_LENGTH(0)))
#define NLA_PAYLOAD(nla)	((int)((nla)->nla_len) - NLA_LENGTH(0))

LIB_EXPORT bool l_genl_attr_init(struct l_genl_attr *attr,
						struct l_genl_msg *msg)
{
	const struct nlattr *nla;
	uint32_t len;

	if (unlikely(!attr) || unlikely(!msg))
		return false;

	if (!msg->data || msg->len < NLMSG_HDRLEN + GENL_HDRLEN)
		return false;

	nla = msg->data + NLMSG_HDRLEN + GENL_HDRLEN;
	len = msg->len - NLMSG_HDRLEN - GENL_HDRLEN;

	if (!NLA_OK(nla, len))
		return false;

	attr->msg = msg;
	attr->data = NULL;
	attr->len = 0;
	attr->next_data = nla;
	attr->next_len = len;

	return true;
}

LIB_EXPORT bool l_genl_attr_next(struct l_genl_attr *attr,
						uint16_t *type,
						uint16_t *len,
						const void **data)
{
	const struct nlattr *nla;

	if (unlikely(!attr))
		return false;

	nla = attr->next_data;

	if (!NLA_OK(nla, attr->next_len))
		return false;

	if (type)
		*type = nla->nla_type & NLA_TYPE_MASK;

	if (len)
		*len = NLA_PAYLOAD(nla);

	if (data)
		*data = NLA_DATA(nla);

	attr->data = attr->next_data;
	attr->len = attr->next_len;

	attr->next_data = NLA_NEXT(nla, attr->next_len);

	return true;
}

LIB_EXPORT bool l_genl_attr_recurse(struct l_genl_attr *attr,
						struct l_genl_attr *nested)
{
	const struct nlattr *nla;

	if (unlikely(!attr) || unlikely(!nested))
		return false;

	nla = attr->data;
	if (!nla)
		return false;

	nested->msg = attr->msg;
	nested->data = NULL;
	nested->len = 0;
	nested->next_data = NLA_DATA(nla);
	nested->next_len = NLA_PAYLOAD(nla);

	return true;
}

static void family_ops(struct l_genl_family *family, struct l_genl_attr *attr)
{
	uint16_t type, len;
	const void *data;

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		struct l_genl_attr attr_op;
		uint32_t id = 0, flags = 0;

		l_genl_attr_recurse(attr, &attr_op);

		while (l_genl_attr_next(&attr_op, &type, &len, &data)) {
			switch (type) {
			case CTRL_ATTR_OP_ID:
				id = *((uint32_t *) data);
				break;
			case CTRL_ATTR_OP_FLAGS:
				flags = *((uint32_t *) data);
				break;
			}
		}

		if (id > 0)
			family_add_op(family, id, flags);
	}
}

static void family_mcast_groups(struct l_genl_family *family,
						struct l_genl_attr *attr)
{
	uint16_t type, len;
	const void *data;

	while (l_genl_attr_next(attr, &type, &len, &data)) {
		struct l_genl_attr attr_grp;
		const char *name = NULL;
		uint32_t id = 0;

		l_genl_attr_recurse(attr, &attr_grp);

		while (l_genl_attr_next(&attr_grp, &type, &len, &data)) {
			switch (type) {
			case CTRL_ATTR_MCAST_GRP_NAME:
				name = data;
				break;
			case CTRL_ATTR_MCAST_GRP_ID:
				id = *((uint32_t *) data);
				break;
			}
		}

		if (name && id > 0)
			family_add_mcast(family, name, id);
	}
}

static void get_family_callback(struct l_genl_msg *msg, void *user_data)
{
	struct l_genl_family *family = user_data;
	struct l_genl_attr attr, nested;
	uint16_t type, len;
	const void *data;
	int error;

	family->nlctrl_cmd = 0;

	if (family->id > 0)
		return;

	error = l_genl_msg_get_error(msg);
	if (error < 0) {
		if (family->watch_vanished)
			family->watch_vanished(family->watch_data);
		return;
	}

	if (!l_genl_attr_init(&attr, msg))
		return;

	while (l_genl_attr_next(&attr, &type, &len, &data)) {
		switch (type) {
		case CTRL_ATTR_FAMILY_ID:
			family->id = *((uint16_t *) data);
			break;
		case CTRL_ATTR_FAMILY_NAME:
			strncpy(family->name, data, GENL_NAMSIZ);
			break;
		case CTRL_ATTR_VERSION:
			family->version = *((uint32_t *) data);
			break;
		case CTRL_ATTR_HDRSIZE:
			family->hdrsize = *((uint32_t *) data);
			break;
		case CTRL_ATTR_MAXATTR:
			family->maxattr = *((uint32_t *) data);
			break;
		case CTRL_ATTR_OPS:
			if (l_genl_attr_recurse(&attr, &nested))
				family_ops(family, &nested);
			break;
		case CTRL_ATTR_MCAST_GROUPS:
			if (l_genl_attr_recurse(&attr, &nested))
				family_mcast_groups(family, &nested);
			break;
		}
	}

	if (family->watch_appeared)
		family->watch_appeared(family->watch_data);
}

LIB_EXPORT struct l_genl_family *l_genl_family_new(struct l_genl *genl,
							const char *name)
{
	struct l_genl_family *family;
	struct l_genl_msg *msg;

	if (unlikely(!genl) || unlikely(!name))
		return NULL;

	family = family_alloc(genl, name);
	if (!family)
		return NULL;

	msg = l_genl_msg_new_sized(CTRL_CMD_GETFAMILY, NLA_HDRLEN + GENL_NAMSIZ);

	l_genl_msg_append_attr(msg, CTRL_ATTR_FAMILY_NAME,
						GENL_NAMSIZ, family->name);

	family->nlctrl_cmd = l_genl_family_send(genl->nlctrl, msg,
					get_family_callback, family, NULL);

	if (!family->nlctrl_cmd) {
		family_free(family);
		return NULL;
	}

	l_queue_push_tail(genl->family_list, family);

	return family;
}

LIB_EXPORT struct l_genl_family *l_genl_family_ref(
						struct l_genl_family *family)
{
	if (unlikely(!family))
		return NULL;

	__sync_fetch_and_add(&family->ref_count, 1);

	return family;
}

LIB_EXPORT void l_genl_family_unref(struct l_genl_family *family)
{
	struct l_genl *genl;

	if (unlikely(!family))
		return;

	if (__sync_sub_and_fetch(&family->ref_count, 1))
		return;

	if (family->nlctrl_cmd > 0)
		l_genl_family_cancel(family, family->nlctrl_cmd);

	genl = family->genl;
	if (genl)
		l_queue_remove(genl->family_list, family);

	l_queue_destroy(family->op_list, op_free);

	l_queue_foreach(family->mcast_list, mcast_free, genl);

	l_queue_destroy(family->mcast_list, NULL);
	family->mcast_list = NULL;

	if (family->id > 0 && family->watch_vanished)
		family->watch_vanished(family->watch_data);

	if (family->watch_destroy)
		family->watch_destroy(family->watch_data);

	l_free(family);
}

LIB_EXPORT bool l_genl_family_set_watches(struct l_genl_family *family,
						l_genl_watch_func_t appeared,
						l_genl_watch_func_t vanished,
						void *user_data,
						l_genl_destroy_func_t destroy)
{
	if (unlikely(!family))
		return false;

	if (family->watch_destroy)
		family->watch_destroy(family->watch_data);

	family->watch_appeared = appeared;
	family->watch_vanished = vanished;
	family->watch_destroy = destroy;
	family->watch_data = user_data;

	return true;
}

LIB_EXPORT uint32_t l_genl_family_get_version(struct l_genl_family *family)
{
	if (unlikely(!family))
		return 0;

	return family->version;
}

static bool match_op_id(const void *a, const void *b)
{
	const struct genl_op *op = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return op->id == id;
}

LIB_EXPORT bool l_genl_family_can_send(struct l_genl_family *family,
								uint8_t cmd)
{
	struct genl_op *op;

	if (unlikely(!family))
		return false;

	op = l_queue_find(family->op_list, match_op_id, L_UINT_TO_PTR(cmd));
	if (!op)
		return false;

	if (op->flags & GENL_CMD_CAP_DO)
		return true;

	return false;
}

LIB_EXPORT bool l_genl_family_can_dump(struct l_genl_family *family,
								uint8_t cmd)
{
	struct genl_op *op;

	if (!family)
		return false;

	op = l_queue_find(family->op_list, match_op_id, L_UINT_TO_PTR(cmd));
	if (!op)
		return false;

	if (op->flags & GENL_CMD_CAP_DUMP)
		return true;

	return false;
}

static unsigned int send_common(struct l_genl_family *family, uint16_t flags,
				struct l_genl_msg *msg, l_genl_msg_func_t callback,
				void *user_data, l_genl_destroy_func_t destroy)
{
	struct l_genl *genl;
	struct genl_request *request;

	if (!family || !msg)
		return 0;

	genl = family->genl;
	if (!genl)
		return 0;

	request = l_new(struct genl_request, 1);

	request->type = family->id;
	request->flags = NLM_F_REQUEST | flags;

	request->msg = msg;

	request->callback = callback;
	request->destroy = destroy;
	request->user_data = user_data;

	if (genl->next_request_id < 1)
		genl->next_request_id = 1;

	request->id = genl->next_request_id++;

	l_queue_push_tail(genl->request_queue, request);

	wakeup_writer(genl);

	return request->id;
}

LIB_EXPORT unsigned int l_genl_family_send(struct l_genl_family *family,
						struct l_genl_msg *msg,
						l_genl_msg_func_t callback,
						void *user_data,
						l_genl_destroy_func_t destroy)
{
	return send_common(family, NLM_F_ACK, msg, callback,
						user_data, destroy);
}

LIB_EXPORT unsigned int l_genl_family_dump(struct l_genl_family *family,
						struct l_genl_msg *msg,
						l_genl_msg_func_t callback,
						void *user_data,
						l_genl_destroy_func_t destroy)
{
	return send_common(family, NLM_F_ACK | NLM_F_DUMP, msg, callback,
							user_data, destroy);
}

static bool match_request_id(const void *a, const void *b)
{
	const struct genl_request *request = a;
	unsigned int id = L_PTR_TO_UINT(b);

	return request->id == id;
}

LIB_EXPORT bool l_genl_family_cancel(struct l_genl_family *family,
							unsigned int id)
{
	struct l_genl *genl;
	struct genl_request *request;

	if (unlikely(!family) || unlikely(!id))
		return false;

	genl = family->genl;
	if (!genl)
		return false;

	request = l_queue_remove_if(genl->request_queue, match_request_id,
							L_UINT_TO_PTR(id));
	if (request)
		goto done;

	request = l_queue_remove_if(genl->pending_list, match_request_id,
							L_UINT_TO_PTR(id));
	if (!request)
		return false;

done:
	destroy_request(request);

	return true;
}

static void add_membership(struct l_genl *genl, struct genl_mcast *mcast)
{
	int group = mcast->id;

	if (mcast->users > 0)
		return;

	if (setsockopt(genl->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
						&group, sizeof(group)) < 0)
		return;

	mcast->users++;
}

LIB_EXPORT bool l_genl_family_has_group(struct l_genl_family *family,
							const char *group)
{
	struct genl_mcast *mcast;

	if (unlikely(!family))
		return false;

	mcast = l_queue_find(family->mcast_list, match_mcast_name,
							(char *) group);
	if (!mcast)
		return false;

	return true;
}

LIB_EXPORT unsigned int l_genl_family_register(struct l_genl_family *family,
						const char *group,
						l_genl_msg_func_t callback,
						void *user_data,
						l_genl_destroy_func_t destroy)
{
	struct l_genl *genl;
	struct genl_mcast_notify *notify;
	struct genl_mcast *mcast;

	if (unlikely(!family) || unlikely(!group))
		return 0;

	genl = family->genl;
	if (!genl)
		return 0;

	mcast = l_queue_find(family->mcast_list, match_mcast_name,
							(char *) group);
	if (!mcast)
		return 0;

	notify = l_new(struct genl_mcast_notify, 1);

	notify->type = family->id;
	notify->group = mcast->id;

	notify->callback = callback;
	notify->destroy = destroy;
	notify->user_data = user_data;

	if (genl->next_notify_id < 1)
		genl->next_notify_id = 1;

	notify->id = genl->next_notify_id++;

	l_queue_push_tail(genl->notify_list, notify);

	add_membership(genl, mcast);

	return notify->id;
}

static bool match_notify_id(const void *a, const void *b)
{
	const struct genl_mcast_notify *notify = a;
	unsigned int id = L_PTR_TO_UINT(b);

	return notify->id == id;
}

LIB_EXPORT bool l_genl_family_unregister(struct l_genl_family *family,
							unsigned int id)
{
	struct l_genl *genl;
	struct genl_mcast_notify *notify;

	if (!family || !id)
		return false;

	genl = family->genl;
	if (!genl)
		return false;

	notify = l_queue_remove_if(genl->notify_list, match_notify_id,
							L_UINT_TO_PTR(id));
	if (!notify)
		return false;

	destroy_notify(notify);

	return true;
}
