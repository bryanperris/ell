/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2018  Intel Corporation. All rights reserved.
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

#include <netinet/ip.h>
#include <net/ethernet.h>
#include <linux/types.h>
#include <net/if_arp.h>
#include <errno.h>

#include "private.h"
#include "random.h"
#include "time.h"
#include "net.h"
#include "timeout.h"
#include "dhcp.h"
#include "dhcp-private.h"

#define CLIENT_DEBUG(fmt, args...)					\
	l_util_debug(client->debug_handler, client->debug_data,		\
			"%s:%i " fmt, __func__, __LINE__, ## args)
#define CLIENT_ENTER_STATE(s)						\
	l_util_debug(client->debug_handler, client->debug_data,		\
			"%s:%i Entering state: " #s,			\
			__func__, __LINE__);				\
	client->state = (s)

#define BITS_PER_LONG (sizeof(unsigned long) * 8)

#define DHCP_OPTION_PAD 0 /* RFC 2132, Section 3.1 */
#define DHCP_OPTION_END 255 /* RFC 2132, Section 3.2 */

/* RFC 2132, Section 9.3. Option Overload */
#define DHCP_OPTION_OVERLOAD 52
enum dhcp_option_overload {
	DHCP_OVERLOAD_FILE = 1,
	DHCP_OVERLOAD_SNAME = 2,
	DHCP_OVERLOAD_BOTH = 3,
};

/* RFC 2132, Section 9.6. DHCP Message Type */
#define DHCP_OPTION_MESSAGE_TYPE 53
enum dhcp_message_type {
	DHCP_MESSAGE_TYPE_DISCOVER = 1,
	DHCP_MESSAGE_TYPE_OFFER = 2,
	DHCP_MESSAGE_TYPE_REQUEST = 3,
	DHCP_MESSAGE_TYPE_DECLINE = 4,
	DHCP_MESSAGE_TYPE_ACK = 5,
	DHCP_MESSAGE_TYPE_NAK = 6,
	DHCP_MESSAGE_TYPE_RELEASE = 7,
	DHCP_MESSAGE_TYPE_INFORM = 8,
};

#define DHCP_OPTION_PARAMETER_REQUEST_LIST 55 /* Section 9.8 */
#define DHCP_OPTION_MAXIMUM_MESSAGE_SIZE 57 /* Section 9.10 */
#define DHCP_OPTION_CLIENT_IDENTIFIER 61 /* Section 9.14 */

enum dhcp_state {
	DHCP_STATE_INIT,
	DHCP_STATE_SELECTING,
	DHCP_STATE_INIT_REBOOT,
	DHCP_STATE_REBOOTING,
	DHCP_STATE_REQUESTING,
	DHCP_STATE_BOUND,
	DHCP_STATE_RENEWING,
	DHCP_STATE_REBINDING,
};

const char *_dhcp_message_type_to_string(uint8_t type)
{
	switch(type) {
	case DHCP_MESSAGE_TYPE_DISCOVER:
		return "DHCPDISCOVER";
	case DHCP_MESSAGE_TYPE_OFFER:
		return "DHCPOFFER";
	case DHCP_MESSAGE_TYPE_REQUEST:
		return "DHCPREQUEST";
	case DHCP_MESSAGE_TYPE_DECLINE:
		return "DHCPDECLINE";
	case DHCP_MESSAGE_TYPE_ACK:
		return "DHCPACK";
	case DHCP_MESSAGE_TYPE_NAK:
		return "DHCPNAK";
	case DHCP_MESSAGE_TYPE_RELEASE:
		return "DHCPRELEASE";
	default:
		return "unknown";
	}
}

const char *_dhcp_option_to_string(uint8_t option)
{
	switch (option) {
	case DHCP_OPTION_PAD:
		return "Pad";
	case L_DHCP_OPTION_SUBNET_MASK:
		return "Subnet Mask";
	case L_DHCP_OPTION_ROUTER:
		return "Router";
	case L_DHCP_OPTION_DOMAIN_NAME_SERVER:
		return "Domain Name Server";
	case L_DHCP_OPTION_HOST_NAME:
		return "Host Name";
	case L_DHCP_OPTION_DOMAIN_NAME:
		return "Domain Name";
	case L_DHCP_OPTION_BROADCAST_ADDRESS:
		return "Broadcast Address";
	case L_DHCP_OPTION_NTP_SERVERS:
		return "NTP Servers";
	case L_DHCP_OPTION_REQUESTED_IP_ADDRESS:
		return "IP Address";
	case L_DHCP_OPTION_IP_ADDRESS_LEASE_TIME:
		return "IP Address Lease Time";
	case DHCP_OPTION_OVERLOAD:
		return "Overload";
	case DHCP_OPTION_MESSAGE_TYPE:
		return "DHCP Message Type";
	case L_DHCP_OPTION_SERVER_IDENTIFIER:
		return "Server Identifier";
	case DHCP_OPTION_PARAMETER_REQUEST_LIST:
		return "Parameter Request List";
	case DHCP_OPTION_MAXIMUM_MESSAGE_SIZE:
		return "Maximum Message Size";
	case L_DHCP_OPTION_RENEWAL_T1_TIME:
		return "Renewal Time";
	case L_DHCP_OPTION_REBINDING_T2_TIME:
		return "Rebinding Time";
	case DHCP_OPTION_CLIENT_IDENTIFIER:
		return "Client Identifier";
	case DHCP_OPTION_END:
		return "End";
	default:
		return "unknown";
	};
}

bool _dhcp_message_iter_init(struct dhcp_message_iter *iter,
				const struct dhcp_message *message, size_t len)
{
	if (!message)
		return false;

	if (len < sizeof(struct dhcp_message))
		return false;

	if (L_BE32_TO_CPU(message->magic) != DHCP_MAGIC)
		return false;

	memset(iter, 0, sizeof(*iter));
	iter->message = message;
	iter->message_len = len;
	iter->max = len - sizeof(struct dhcp_message);
	iter->options = message->options;
	iter->can_overload = true;

	return true;
}

static bool next_option(struct dhcp_message_iter *iter,
				uint8_t *t, uint8_t *l, const void **v)
{
	uint8_t type;
	uint8_t len;

	while (iter->pos < iter->max) {
		type = iter->options[iter->pos];

		switch (type) {
		case DHCP_OPTION_PAD:
			iter->pos += 1;
			continue;
		case DHCP_OPTION_END:
			return false;
		default:
			break;
		}

		if (iter->pos + 2 >= iter->max)
			return false;

		len = iter->options[iter->pos + 1];

		if (iter->pos + 2 + len > iter->max)
			return false;

		*t = type;
		*l = len;
		*v = &iter->options[iter->pos + 2];

		iter->pos += 2 + len;
		return true;
	}

	return false;
}

bool _dhcp_message_iter_next(struct dhcp_message_iter *iter, uint8_t *type,
				uint8_t *len, const void **data)
{
	bool r;
	uint8_t t, l;
	const void *v;

	do {
		r = next_option(iter, &t, &l, &v);
		if (!r) {
			iter->can_overload = false;

			if (iter->overload_file) {
				iter->options = iter->message->file;
				iter->pos = 0;
				iter->max = sizeof(iter->message->file);
				iter->overload_file = false;
				continue;
			}

			if (iter->overload_sname) {
				iter->options = iter->message->sname;
				iter->pos = 0;
				iter->max = sizeof(iter->message->sname);
				iter->overload_sname = false;
				continue;
			}

			return r;
		}

		switch (t) {
		case DHCP_OPTION_OVERLOAD:
			if (l != 1)
				continue;

			if (!iter->can_overload)
				continue;

			if (l_get_u8(v) & DHCP_OVERLOAD_FILE)
				iter->overload_file = true;

			if (l_get_u8(v) & DHCP_OVERLOAD_SNAME)
				iter->overload_sname = true;

			continue;
		default:
			if (type)
				*type = t;

			if (len)
				*len = l;

			if (data)
				*data = v;
			return r;
		}
	} while (true);

	return false;
}

int _dhcp_option_append(uint8_t **buf, size_t *buflen, uint8_t code,
					size_t optlen, const void *optval)
{
	if (!buf || !buflen)
		return -EINVAL;

	switch (code) {

	case DHCP_OPTION_PAD:
	case DHCP_OPTION_END:
		if (*buflen < 1)
			return -ENOBUFS;

		(*buf)[0] = code;
		*buf += 1;
		*buflen -= 1;
		break;

	default:
		if (*buflen < optlen + 2)
			return -ENOBUFS;

		if (!optval)
			return -EINVAL;

		(*buf)[0] = code;
		(*buf)[1] = optlen;
		memcpy(&(*buf)[2], optval, optlen);

		*buf += optlen + 2;
		*buflen -= (optlen + 2);

		break;
	}

	return 0;
}

static int dhcp_append_prl(const unsigned long *reqopts,
					uint8_t **buf, size_t *buflen)
{
	uint8_t optlen = 0;
	unsigned int i;
	unsigned int j;

	if (!buf || !buflen)
		return -EINVAL;

	for (i = 0; i < 256 / BITS_PER_LONG; i++)
		optlen += __builtin_popcountl(reqopts[i]);

	/*
	 * This function assumes that there's enough space to put the PRL
	 * into the buffer without resorting to file or sname overloading
	 */
	if (*buflen < optlen + 2U)
		return -ENOBUFS;

	i = 0;
	(*buf)[i++] = DHCP_OPTION_PARAMETER_REQUEST_LIST;
	(*buf)[i++] = optlen;

	for (j = 0; j < 256; j++) {
		if (reqopts[j / BITS_PER_LONG] & 1UL << (j % BITS_PER_LONG))
			(*buf)[i++] = j;
	}

	*buf += optlen + 2;
	*buflen -= (optlen + 2);

	return 0;
}

static int dhcp_message_init(struct dhcp_message *message,
				enum dhcp_op_code op,
				uint8_t type, uint32_t xid,
				uint8_t **opt, size_t *optlen)
{
	int err;

	message->op = op;
	message->xid = L_CPU_TO_BE32(xid);
	message->magic = L_CPU_TO_BE32(DHCP_MAGIC);
	*opt = (uint8_t *)(message + 1);

	err = _dhcp_option_append(opt, optlen,
					DHCP_OPTION_MESSAGE_TYPE, 1, &type);
	if (err < 0)
		return err;

	return 0;
}

static void dhcp_message_set_address_type(struct dhcp_message *message,
						uint8_t addr_type,
						uint8_t addr_len)
{
	message->htype = addr_type;

	switch (addr_type) {
	case ARPHRD_ETHER:
		message->hlen = addr_len;
		break;
	default:
		message->hlen = 0;
	}
}

static inline int dhcp_message_optimize(struct dhcp_message *message,
					const uint8_t *end)
{
	/*
	 * Don't bother sending a full sized dhcp_message as it is most likely
	 * mostly zeros.  Instead truncate it at DHCP_OPTION_END and align to
	 * the nearest 4 byte boundary.  Many implementations expect a packet
	 * of a certain size or it is filtered, so we cap the length in
	 * accordance to RFC 1542:
	 * "The IP Total Length and UDP Length must be large enough to contain
	 * the minimal BOOTP header of 300 octets"
	 */
	size_t len = align_len(end - (uint8_t *) message, 4);
	if (len < 300)
		len = 300;

	return len;
}

#define DHCP_MIN_OPTIONS_SIZE 312

struct l_dhcp_client {
	enum dhcp_state state;
	unsigned long request_options[256 / BITS_PER_LONG];
	uint32_t ifindex;
	char *ifname;
	uint8_t addr[6];
	uint8_t addr_len;
	uint8_t addr_type;
	char *hostname;
	uint32_t xid;
	struct dhcp_transport *transport;
	uint64_t start_t;
	struct l_timeout *timeout_resend;
	struct l_timeout *timeout_lease;
	struct l_dhcp_lease *lease;
	uint8_t attempt;
	l_dhcp_client_event_cb_t event_handler;
	void *event_data;
	l_dhcp_destroy_cb_t event_destroy;
	l_dhcp_debug_cb_t debug_handler;
	l_dhcp_destroy_cb_t debug_destroy;
	void *debug_data;
	bool have_addr : 1;
	bool override_xid : 1;
};

static inline void dhcp_enable_option(struct l_dhcp_client *client,
								uint8_t option)
{
	client->request_options[option / BITS_PER_LONG] |=
						1UL << (option % BITS_PER_LONG);
}

static uint16_t dhcp_attempt_secs(uint64_t start)
{
	uint64_t now = l_time_now();
	uint64_t elapsed = l_time_to_secs(now - start);

	if (elapsed == 0)
		return 1;

	if (elapsed > UINT16_MAX)
		return UINT16_MAX;

	return elapsed;
}

/*
 * Takes a time in seconds and produces a fuzzed value that can be directly
 * used by l_timeout_modify_ms
 */
static uint64_t dhcp_fuzz_secs(uint32_t secs)
{
	uint64_t ms = secs * 1000;
	uint32_t r = l_getrandom_uint32();

	/*
	 * RFC2132, Section 4.1:
	 * DHCP clients are responsible for all message retransmission.  The
	 * client MUST adopt a retransmission strategy that incorporates a
	 * randomized exponential backoff algorithm to determine the delay
	 * between retransmissions.
	 *
	 * and later in the same paragraph:
	 * For example, in a 10Mb/sec Ethernet internetwork, the delay before
	 * the first retransmission SHOULD be 4 seconds randomized by the
	 * value of a uniform random number chosen from the range -1 to +1.
	 * Clients with clocks that provide resolution granularity of less than
	 * one second may choose a non-integer randomization value.
	 */
	if (r & 0x80000000)
		ms += r & 0x3ff;
	else
		ms -= r & 0x3ff;

	return ms;
}

static uint32_t dhcp_rebind_renew_retry_time(uint64_t start_t, uint32_t expiry)
{
	uint64_t now = l_time_now();
	uint32_t relative_now;
	uint32_t retry_time;

	/*
	 * RFC 2131, Section 4.4.5:
	 * "   In both RENEWING and REBINDING states, if the client receives no
	 * response to its DHCPREQUEST message, the client SHOULD wait one-half
	 * of the remaining time until T2 (in RENEWING state) and one-half of
	 * the remaining lease time (in REBINDING state), down to a minimum of
	 * 60 seconds, before retransmitting the DHCPREQUEST message.
	 */
	relative_now = l_time_to_secs(now - start_t);
	retry_time = (expiry - relative_now) / 2;

	if (retry_time < 60)
		retry_time = 60;

	return retry_time;
}

static int client_message_init(struct l_dhcp_client *client,
					struct dhcp_message *message,
					uint8_t type,
					uint8_t **opt, size_t *optlen)
{
	int err;
	uint16_t max_size;

	err = dhcp_message_init(message, DHCP_OP_CODE_BOOTREQUEST,
				type, client->xid, opt, optlen);
	if (err < 0)
		return err;

	dhcp_message_set_address_type(message, client->addr_type,
							client->addr_len);
	/*
	 * RFC2132 section 4.1.1:
	 * The client MUST include its hardware address in the ’chaddr’ field,
	 * if necessary for delivery of DHCP reply messages.  Non-Ethernet
	 * interfaces will leave 'chaddr' empty and use the client identifier
	 * instead
	 */
	if (client->addr_type == ARPHRD_ETHER)
		memcpy(message->chaddr, &client->addr, client->addr_len);

	/*
	 * Althrough RFC 2131 says that secs should be initialized to 0,
	 * some servers refuse to give us a lease unless we set this to a
	 * non-zero value
	 */
	message->secs = L_CPU_TO_BE16(dhcp_attempt_secs(client->start_t));

	err = dhcp_append_prl(client->request_options, opt, optlen);
	if (err < 0)
		return err;

	/*
	 * Set the maximum DHCP message size to the minimum legal value.  This
	 * helps some buggy DHCP servers to not send bigger packets
	 */
	max_size = L_CPU_TO_BE16(576);
	err = _dhcp_option_append(opt, optlen,
					DHCP_OPTION_MAXIMUM_MESSAGE_SIZE,
					2, &max_size);
	if (err < 0)
		return err;

	return 0;
}

static void dhcp_client_event_notify(struct l_dhcp_client *client,
						enum l_dhcp_client_event event)
{
	if (client->event_handler)
		client->event_handler(client, event, client->event_data);
}

static int dhcp_client_send_discover(struct l_dhcp_client *client)
{
	uint8_t *opt;
	size_t optlen = DHCP_MIN_OPTIONS_SIZE;
	size_t len = sizeof(struct dhcp_message) + optlen;
	L_AUTO_FREE_VAR(struct dhcp_message *, discover);
	int err;

	CLIENT_DEBUG("");

	discover = (struct dhcp_message *) l_new(uint8_t, len);

	err = client_message_init(client, discover,
					DHCP_MESSAGE_TYPE_DISCOVER,
					&opt, &optlen);
	if (err < 0)
		return err;

	if (client->hostname) {
		err = _dhcp_option_append(&opt, &optlen,
						L_DHCP_OPTION_HOST_NAME,
						strlen(client->hostname),
						client->hostname);
		if (err < 0)
			return err;
	}

	err = _dhcp_option_append(&opt, &optlen, DHCP_OPTION_END, 0, NULL);
	if (err < 0)
		return err;

	len = dhcp_message_optimize(discover, opt);

	return client->transport->broadcast(client->transport,
					INADDR_ANY, DHCP_PORT_CLIENT,
					INADDR_BROADCAST, DHCP_PORT_SERVER,
					discover, len);
}

static int dhcp_client_send_request(struct l_dhcp_client *client)
{
	uint8_t *opt;
	size_t optlen = DHCP_MIN_OPTIONS_SIZE;
	size_t len = sizeof(struct dhcp_message) + optlen;
	L_AUTO_FREE_VAR(struct dhcp_message *, request);
	int err;

	CLIENT_DEBUG("");

	request = (struct dhcp_message *) l_new(uint8_t, len);

	err = client_message_init(client, request,
					DHCP_MESSAGE_TYPE_REQUEST,
					&opt, &optlen);
	if (err < 0)
		return err;

	switch (client->state) {
	case DHCP_STATE_REQUESTING:
		/*
		 * RFC 2131, Section 4.3.2:
		 * "If the DHCPREQUEST message contains a 'server identifier'
		 * option, the message is in response to a DHCPOFFER message."
		 *
		 * and
		 *
		 * "DHCPREQUEST generated during SELECTING state:
		 * Client inserts the address of the selected server in
		 * 'server identifier', 'ciaddr' MUST be zero, 'requested IP
		 * address' MUST be filled in with the yiaddr value from the
		 * chosen DHCPOFFER."
		 *
		 * NOTE: 'SELECTING' is meant to be 'REQUESTING' in the RFC
		 */
		err = _dhcp_option_append(&opt, &optlen,
					L_DHCP_OPTION_SERVER_IDENTIFIER,
					4, &client->lease->server_address);
		if (err < 0)
			return err;

		err = _dhcp_option_append(&opt, &optlen,
					L_DHCP_OPTION_REQUESTED_IP_ADDRESS,
					4, &client->lease->address);
		if (err < 0)
			return err;
		break;
	case DHCP_STATE_RENEWING:
	case DHCP_STATE_REBINDING:
		request->ciaddr = client->lease->address;
		break;

	case DHCP_STATE_INIT:
	case DHCP_STATE_SELECTING:
	case DHCP_STATE_INIT_REBOOT:
	case DHCP_STATE_REBOOTING:
	case DHCP_STATE_BOUND:
		return -EINVAL;
	}

	if (client->hostname) {
		err = _dhcp_option_append(&opt, &optlen,
						L_DHCP_OPTION_HOST_NAME,
						strlen(client->hostname),
						client->hostname);
		if (err < 0)
			return err;
	}

	err = _dhcp_option_append(&opt, &optlen, DHCP_OPTION_END, 0, NULL);
	if (err < 0)
		return err;

	len = dhcp_message_optimize(request, opt);

	/*
	 * RFC2131, Section 4.1:
	 * "DHCP clients MUST use the IP address provided in the
	 * 'server identifier' option for any unicast requests to the DHCP
	 * server.
	 */
	if (client->state == DHCP_STATE_RENEWING) {
		struct sockaddr_in si;
		memset(&si, 0, sizeof(si));
		si.sin_family = AF_INET;
		si.sin_port = L_CPU_TO_BE16(DHCP_PORT_SERVER);
		si.sin_addr.s_addr = client->lease->server_address;
		return client->transport->send(client->transport,
							&si, request, len);
	}

	return client->transport->broadcast(client->transport,
					INADDR_ANY, DHCP_PORT_CLIENT,
					INADDR_BROADCAST, DHCP_PORT_SERVER,
					request, len);
}

static void dhcp_client_timeout_resend(struct l_timeout *timeout,
								void *user_data)
{
	struct l_dhcp_client *client = user_data;
	unsigned int next_timeout = 0;

	CLIENT_DEBUG("");

	switch (client->state) {
	case DHCP_STATE_SELECTING:
		if (dhcp_client_send_discover(client) < 0)
			goto error;
		break;
	case DHCP_STATE_RENEWING:
	case DHCP_STATE_REQUESTING:
	case DHCP_STATE_REBINDING:
		if (dhcp_client_send_request(client) < 0)
			goto error;
		break;
	case DHCP_STATE_INIT:
	case DHCP_STATE_INIT_REBOOT:
	case DHCP_STATE_REBOOTING:
	case DHCP_STATE_BOUND:
		break;
	}

	switch (client->state) {
	case DHCP_STATE_RENEWING:
		next_timeout = dhcp_rebind_renew_retry_time(client->start_t,
							client->lease->t2);
		break;
	case DHCP_STATE_REBINDING:
		next_timeout = dhcp_rebind_renew_retry_time(client->start_t,
						client->lease->lifetime);
		break;
	case DHCP_STATE_REQUESTING:
	case DHCP_STATE_SELECTING:
		/*
		 * RFC 2131 Section 4.1:
		 * "The retransmission delay SHOULD be doubled with subsequent
		 * retransmissions up to a maximum of 64 seconds.
		 */
		client->attempt += 1;
		next_timeout = minsize(2 << client->attempt, 64);
		break;
	case DHCP_STATE_INIT:
	case DHCP_STATE_INIT_REBOOT:
	case DHCP_STATE_REBOOTING:
	case DHCP_STATE_BOUND:
		break;
	};

	if (next_timeout)
		l_timeout_modify_ms(timeout, dhcp_fuzz_secs(next_timeout));

	return;

error:
	l_dhcp_client_stop(client);
}

static void dhcp_client_t2_expired(struct l_timeout *timeout, void *user_data)
{
	struct l_dhcp_client *client = user_data;

	CLIENT_DEBUG("");

	/*
	 * If we got here, then resend_timeout is active, with a timeout
	 * set originally for ~60 seconds.  So we simply set the new state
	 * and wait for the timer to fire
	 */
	CLIENT_ENTER_STATE(DHCP_STATE_REBINDING);

	/* TODO: Start timer for the expiration time */
}

static void dhcp_client_t1_expired(struct l_timeout *timeout, void *user_data)
{
	struct l_dhcp_client *client = user_data;
	uint32_t next_timeout;

	CLIENT_DEBUG("");

	CLIENT_ENTER_STATE(DHCP_STATE_RENEWING);
	client->attempt = 1;

	if (dhcp_client_send_request(client) < 0)
		goto error;

	next_timeout = client->lease->t2 - client->lease->t1;
	l_timeout_modify_ms(client->timeout_lease,
						dhcp_fuzz_secs(next_timeout));
	l_timeout_set_callback(client->timeout_lease, dhcp_client_t2_expired,
				client, NULL);

	next_timeout = dhcp_rebind_renew_retry_time(client->start_t,
							client->lease->t2);
	client->timeout_resend =
		l_timeout_create_ms(dhcp_fuzz_secs(next_timeout),
					dhcp_client_timeout_resend,
					client, NULL);
	return;

error:
	l_dhcp_client_stop(client);
}

static int dhcp_client_receive_ack(struct l_dhcp_client *client,
					const struct dhcp_message *ack,
					size_t len)
{
	struct dhcp_message_iter iter;
	struct l_dhcp_lease *lease;
	int r;

	CLIENT_DEBUG("");

	if (ack->yiaddr == 0)
		return -ENOMSG;

	if (!_dhcp_message_iter_init(&iter, ack, len))
		return -EINVAL;

	lease = _dhcp_lease_parse_options(&iter);
	if (!lease)
		return -ENOMSG;

	lease->address = ack->yiaddr;

	r = L_DHCP_CLIENT_EVENT_LEASE_RENEWED;

	if (client->lease) {
		if (client->lease->subnet_mask != lease->subnet_mask ||
				client->lease->address != lease->address ||
				client->lease->router != lease->router)
			r = L_DHCP_CLIENT_EVENT_IP_CHANGED;

		_dhcp_lease_free(client->lease);
	}

	client->lease = lease;

	/* In case this is an initial request, override to LEASE_OBTAINED */
	if (client->state == DHCP_STATE_REQUESTING ||
			client->state == DHCP_STATE_REBOOTING)
		r = L_DHCP_CLIENT_EVENT_LEASE_OBTAINED;

	return r;
}

static int dhcp_client_receive_offer(struct l_dhcp_client *client,
					const struct dhcp_message *offer,
					size_t len)
{
	struct dhcp_message_iter iter;

	CLIENT_DEBUG("");

	if (offer->yiaddr == 0)
		return -ENOMSG;

	if (!_dhcp_message_iter_init(&iter, offer, len))
		return -EINVAL;

	client->lease = _dhcp_lease_parse_options(&iter);
	if (!client->lease)
		return -ENOMSG;

	client->lease->address = offer->yiaddr;

	return 0;
}

static void dhcp_client_rx_message(const void *data, size_t len, void *userdata)
{
	struct l_dhcp_client *client = userdata;
	const struct dhcp_message *message = data;
	struct dhcp_message_iter iter;
	uint8_t msg_type = 0;
	uint8_t t, l;
	const void *v;
	int r;

	CLIENT_DEBUG("");

	if (len < sizeof(struct dhcp_message))
		return;

	if (message->op != DHCP_OP_CODE_BOOTREPLY)
		return;

	if (L_BE32_TO_CPU(message->xid) != client->xid)
		return;

	if (memcmp(message->chaddr, client->addr, client->addr_len))
		return;

	if (!_dhcp_message_iter_init(&iter, message, len))
		return;

	while (_dhcp_message_iter_next(&iter, &t, &l, &v) && !msg_type) {
		switch (t) {
		case DHCP_OPTION_MESSAGE_TYPE:
			if (l == 1)
				msg_type = l_get_u8(v);
			break;
		}
	}

	switch (client->state) {
	case DHCP_STATE_INIT:
		return;
	case DHCP_STATE_SELECTING:
		if (msg_type != DHCP_MESSAGE_TYPE_OFFER)
			return;

		if (dhcp_client_receive_offer(client, message, len) < 0)
			return;

		CLIENT_ENTER_STATE(DHCP_STATE_REQUESTING);
		client->attempt = 1;

		if (dhcp_client_send_request(client) < 0)
			goto error;

		l_timeout_modify_ms(client->timeout_resend, dhcp_fuzz_secs(4));
		break;
	case DHCP_STATE_REQUESTING:
	case DHCP_STATE_RENEWING:
	case DHCP_STATE_REBINDING:
		if (msg_type == DHCP_MESSAGE_TYPE_NAK) {
			dhcp_client_event_notify(client,
					L_DHCP_CLIENT_EVENT_NO_LEASE);
			goto error;
		}

		if (msg_type != DHCP_MESSAGE_TYPE_ACK)
			return;

		r = dhcp_client_receive_ack(client, message, len);
		if (r < 0)
			return;

		CLIENT_ENTER_STATE(DHCP_STATE_BOUND);
		l_timeout_remove(client->timeout_resend);
		client->timeout_resend = NULL;

		dhcp_client_event_notify(client, r);

		/*
		 * Start T1, once it expires we will start the T2 timer.  If
		 * we renew the lease, we will end up back here.
		 *
		 * RFC2131, Section 4.4.5 states:
		 * "Times T1 and T2 SHOULD be chosen with some random "fuzz"
		 * around a fixed value, to avoid synchronization of client
		 * reacquisition."
		 */
		l_timeout_remove(client->timeout_lease);
		client->timeout_lease =
			l_timeout_create_ms(dhcp_fuzz_secs(client->lease->t1),
						dhcp_client_t1_expired,
						&client, NULL);

		break;
	case DHCP_STATE_INIT_REBOOT:
	case DHCP_STATE_REBOOTING:
	case DHCP_STATE_BOUND:
		break;
	}

	return;

error:
	l_dhcp_client_stop(client);
}

LIB_EXPORT struct l_dhcp_client *l_dhcp_client_new(uint32_t ifindex)
{
	struct l_dhcp_client *client;

	client = l_new(struct l_dhcp_client, 1);

	client->state = DHCP_STATE_INIT;
	client->ifindex = ifindex;

	/* Enable these options by default */
	dhcp_enable_option(client, L_DHCP_OPTION_SUBNET_MASK);
	dhcp_enable_option(client, L_DHCP_OPTION_ROUTER);
	dhcp_enable_option(client, L_DHCP_OPTION_HOST_NAME);
	dhcp_enable_option(client, L_DHCP_OPTION_DOMAIN_NAME);
	dhcp_enable_option(client, L_DHCP_OPTION_DOMAIN_NAME_SERVER);
	dhcp_enable_option(client, L_DHCP_OPTION_NTP_SERVERS);

	return client;
}

LIB_EXPORT void l_dhcp_client_destroy(struct l_dhcp_client *client)
{
	if (unlikely(!client))
		return;

	l_dhcp_client_stop(client);

	if (client->event_destroy)
		client->event_destroy(client->event_data);

	_dhcp_transport_free(client->transport);
	l_free(client->ifname);
	l_free(client->hostname);

	l_free(client);
}

LIB_EXPORT bool l_dhcp_client_add_request_option(struct l_dhcp_client *client,
								uint8_t option)
{
	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP_STATE_INIT))
		return false;

	switch (option) {
	case DHCP_OPTION_PAD:
	case DHCP_OPTION_END:
	case DHCP_OPTION_OVERLOAD:
	case DHCP_OPTION_MESSAGE_TYPE:
	case DHCP_OPTION_PARAMETER_REQUEST_LIST:
		return false;
	}

	dhcp_enable_option(client, option);

	return true;
}

LIB_EXPORT bool l_dhcp_client_set_address(struct l_dhcp_client *client,
						uint8_t type,
						const uint8_t *addr,
						size_t addr_len)
{
	if (unlikely(!client))
		return false;

	switch (type) {
	case ARPHRD_ETHER:
		if (addr_len != ETH_ALEN)
			return false;
		break;
	default:
		return false;
	}

	client->addr_len = addr_len;
	memcpy(client->addr, addr, addr_len);
	client->addr_type = type;

	client->have_addr = true;

	return true;
}

LIB_EXPORT bool l_dhcp_client_set_interface_name(struct l_dhcp_client *client,
							const char *ifname)
{
	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP_STATE_INIT))
		return false;

	l_free(client->ifname);
	client->ifname = l_strdup(ifname);

	return true;
}

LIB_EXPORT bool l_dhcp_client_set_hostname(struct l_dhcp_client *client,
						const char *hostname)
{
	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP_STATE_INIT))
		return false;

	if (!hostname)
		goto done;

	if (client->hostname && !strcmp(client->hostname, hostname))
		return true;

done:
	l_free(client->hostname);
	client->hostname = l_strdup(hostname);

	return true;
}

bool _dhcp_client_set_transport(struct l_dhcp_client *client,
					struct dhcp_transport *transport)
{
	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP_STATE_INIT))
		return false;

	if (client->transport)
		_dhcp_transport_free(client->transport);

	client->transport = transport;
	return true;
}

void _dhcp_client_override_xid(struct l_dhcp_client *client, uint32_t xid)
{
	client->override_xid = true;
	client->xid = xid;
}

LIB_EXPORT const struct l_dhcp_lease *l_dhcp_client_get_lease(
					const struct l_dhcp_client *client)
{
	if (unlikely(!client))
		return NULL;

	return client->lease;
}

LIB_EXPORT bool l_dhcp_client_start(struct l_dhcp_client *client)
{
	int err;

	if (unlikely(!client))
		return false;

	if (unlikely(client->state != DHCP_STATE_INIT))
		return false;

	if (!client->have_addr) {
		uint8_t mac[6];

		if (!l_net_get_mac_address(client->ifindex, mac))
			return false;

		l_dhcp_client_set_address(client, ARPHRD_ETHER, mac, 6);
	}

	if (!client->ifname) {
		client->ifname = l_net_get_name(client->ifindex);

		if (!client->ifname)
			return false;
	}

	if (!client->transport) {
		client->transport =
			_dhcp_default_transport_new(client->ifindex,
							client->ifname,
							DHCP_PORT_CLIENT);

		if (!client->transport)
			return false;
	}

	if (!client->override_xid)
		l_getrandom(&client->xid, sizeof(client->xid));

	if (client->transport->open)
		if (client->transport->open(client->transport,
							client->xid) < 0)
			return false;

	_dhcp_transport_set_rx_callback(client->transport,
						dhcp_client_rx_message,
						client);

	client->start_t = l_time_now();

	err = dhcp_client_send_discover(client);
	if (err < 0)
		return false;

	client->timeout_resend = l_timeout_create_ms(dhcp_fuzz_secs(4),
						dhcp_client_timeout_resend,
						client, NULL);
	CLIENT_ENTER_STATE(DHCP_STATE_SELECTING);
	client->attempt = 1;

	return true;
}

LIB_EXPORT bool l_dhcp_client_stop(struct l_dhcp_client *client)
{
	if (unlikely(!client))
		return false;

	l_timeout_remove(client->timeout_resend);
	client->timeout_resend = NULL;

	l_timeout_remove(client->timeout_lease);
	client->timeout_lease = NULL;

	if (client->transport && client->transport->close)
		client->transport->close(client->transport);

	client->start_t = 0;
	CLIENT_ENTER_STATE(DHCP_STATE_INIT);

	_dhcp_lease_free(client->lease);
	return true;
}

LIB_EXPORT bool l_dhcp_client_set_event_handler(struct l_dhcp_client *client,
					l_dhcp_client_event_cb_t handler,
					void *userdata,
					l_dhcp_destroy_cb_t destroy)
{
	if (unlikely(!client))
		return false;

	if (client->event_destroy)
		client->event_destroy(client->event_data);

	client->event_handler = handler;
	client->event_data = userdata;
	client->event_destroy = destroy;

	return true;
}

LIB_EXPORT bool l_dhcp_client_set_debug(struct l_dhcp_client *client,
						l_dhcp_debug_cb_t function,
						void *user_data,
						l_dhcp_destroy_cb_t destroy)
{
	if (unlikely(!client))
		return false;

	if (client->debug_destroy)
		client->debug_destroy(client->debug_data);

	client->debug_handler = function;
	client->debug_destroy = destroy;
	client->debug_data = user_data;

	return true;
}
