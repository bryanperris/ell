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
#include <unistd.h>
#include <sys/socket.h>

#include "util.h"
#include "checksum.h"
#include "private.h"

#ifndef AF_ALG
#define AF_ALG	38
#define PF_ALG	AF_ALG

#include <linux/types.h>

struct sockaddr_alg {
	__u16	salg_family;
	__u8	salg_type[14];
	__u32	salg_feat;
	__u32	salg_mask;
	__u8	salg_name[64];
};
#else
#include <linux/if_alg.h>
#endif

/**
 * SECTION:checksum
 * @short_description: Checksum handling
 *
 * Checksum handling
 */

#define is_valid_type(type)  ((type) <= L_CHECKSUM_SHA256)

/**
 * l_checksum:
 *
 * Opague object representing the checksum.
 */
struct l_checksum {
	enum l_checksum_type type;
	int sk;
};

static int create_alg(enum l_checksum_type type)
{
	struct sockaddr_alg salg;
	int sk, nsk;

	sk = socket(PF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -1;

	memset(&salg, 0, sizeof(salg));
	salg.salg_family = AF_ALG;
	strcpy((char *) salg.salg_type, "hash");

	switch (type) {
	case L_CHECKSUM_MD5:
		strcpy((char *) salg.salg_name, "md5");
		break;
	case L_CHECKSUM_SHA1:
		strcpy((char *) salg.salg_name, "sha1");
		break;
	case L_CHECKSUM_SHA256:
		strcpy((char *) salg.salg_name, "sha256");
		break;
	}

	if (bind(sk, (struct sockaddr *) &salg, sizeof(salg)) < 0) {
		close(sk);
		return -1;
	}

	nsk = accept4(sk, NULL, 0, SOCK_CLOEXEC);
	close(sk);

	return nsk;
}

/**
 * l_checksum_new:
 * @type: checksum type
 *
 * Creates new #l_checksum, using the checksum algorithm @type.
 *
 * Returns: a newly allocated #l_checksum object.
 **/
LIB_EXPORT struct l_checksum *l_checksum_new(enum l_checksum_type type)
{
	struct l_checksum *checksum;

	if (!is_valid_type(type))
		return NULL;

	checksum = l_new(struct l_checksum, 1);

	checksum->type = type;
	checksum->sk = create_alg(type);

	if (checksum->sk < 0) {
		l_free(checksum);
		return NULL;
	}

	return checksum;
}

/**
 * l_checksum_free:
 * @checksum: checksum object
 *
 * Frees the memory allocated for @checksum.
 **/
LIB_EXPORT void l_checksum_free(struct l_checksum *checksum)
{
	if (unlikely(!checksum))
		return;

	close(checksum->sk);
	l_free(checksum);
}

/**
 * l_checksum_reset:
 * @checksum: checksum object
 *
 * Resets the internal state of @checksum.
 **/
void l_checksum_reset(struct l_checksum *checksum)
{
	if (unlikely(!checksum))
		return;

	send(checksum->sk, NULL, 0, 0);
}

/**
 * l_checksum_update:
 * @checksum: checksum object
 * @data: data pointer
 * @len: length of data
 *
 * Updates checksum from @data pointer with @len bytes.
 **/
LIB_EXPORT void l_checksum_update(struct l_checksum *checksum,
					const void *data, size_t len)
{
	ssize_t written;

	if (unlikely(!checksum))
		return;

	if (unlikely(!data) || unlikely(!len))
		return;

	written = send(checksum->sk, data, len, MSG_MORE);
	if (written < 0)
		return;
}

void l_checksum_updatev(struct l_checksum *checksum,
					struct iovec *iov, size_t iov_len)
{
	struct msghdr msg;

	if (unlikely(!checksum))
		return;

	if (unlikely(!iov) || unlikely(!iov_len))
		return;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = iov_len;

	sendmsg(checksum->sk, &msg, MSG_MORE);
}

/**
 * l_checksum_get_digest:
 * @checksum: checksum object
 * @digest: digest data pointer
 * @len: length of digest data
 *
 * Gets the digest from @checksum as raw binary data.
 **/
LIB_EXPORT void l_checksum_get_digest(struct l_checksum *checksum,
						void *digest, size_t len)
{
	ssize_t result;

	if (unlikely(!checksum))
		return;

	if (unlikely(!digest) || unlikely(!len))
		return;

	result = recv(checksum->sk, digest, len, 0);
	if (result < 0)
		return;
}

/**
 * l_checksum_get_string:
 * @checksum: checksum object
 *
 * Gets the digest from @checksum as hex encoded string.
 *
 * Returns: a newly allocated hex string
 **/
LIB_EXPORT char *l_checksum_get_string(struct l_checksum *checksum)
{
	unsigned char digest[32];

	if (unlikely(!checksum))
		return NULL;

	l_checksum_get_digest(checksum, digest, sizeof(digest));

	switch (checksum->type) {
	case L_CHECKSUM_MD5:
		return l_util_hexstring(digest, 16);
	case L_CHECKSUM_SHA1:
		return l_util_hexstring(digest, 20);
	case L_CHECKSUM_SHA256:
		return l_util_hexstring(digest, 32);
	}

	return NULL;
}
