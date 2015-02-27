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
#include <sys/types.h>
#include <sys/socket.h>

#include "util.h"
#include "checksum.h"
#include "private.h"

#ifndef HAVE_LINUX_IF_ALG_H
#ifndef HAVE_LINUX_TYPES_H
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
#else
#include <linux/types.h>
#endif

#ifndef AF_ALG
#define AF_ALG	38
#define PF_ALG	AF_ALG
#endif

struct sockaddr_alg {
	__u16	salg_family;
	__u8	salg_type[14];
	__u32	salg_feat;
	__u32	salg_mask;
	__u8	salg_name[64];
};

/* Socket options */
#define ALG_SET_KEY	1

#else
#include <linux/if_alg.h>
#endif

#ifndef SOL_ALG
#define SOL_ALG 279
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
	int sk;
	char alg_name[16];
};

static int create_alg(const char *alg)
{
	struct sockaddr_alg salg;
	int sk;

	sk = socket(PF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -1;

	memset(&salg, 0, sizeof(salg));
	salg.salg_family = AF_ALG;
	strcpy((char *) salg.salg_type, "hash");
	strcpy((char *) salg.salg_name, alg);

	if (bind(sk, (struct sockaddr *) &salg, sizeof(salg)) < 0) {
		close(sk);
		return -1;
	}

	return sk;
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
	const char *name;
	int fd;

	if (!is_valid_type(type))
		return NULL;

	checksum = l_new(struct l_checksum, 1);

	switch (type) {
	case L_CHECKSUM_MD5:
		name = "md5";
		break;
	case L_CHECKSUM_SHA1:
		name = "sha1";
		break;
	case L_CHECKSUM_SHA256:
		name = "sha256";
		break;
	}

	fd = create_alg(name);
	if (fd < 0)
		goto error;

	checksum->sk = accept4(fd, NULL, 0, SOCK_CLOEXEC);
	close(fd);

	if (checksum->sk < 0)
		goto error;

	strcpy(checksum->alg_name, name);

	return checksum;

error:
	l_free(checksum);
	return NULL;
}

LIB_EXPORT struct l_checksum *l_checksum_new_cmac_aes(const void *key,
							size_t key_len)
{
	struct l_checksum *checksum;
	int fd;

	fd = create_alg("cmac(aes)");
	if (fd < 0)
		return NULL;

	if (setsockopt(fd, SOL_ALG, ALG_SET_KEY, key, key_len) < 0) {
		close(fd);
		return NULL;
	}

	checksum = l_new(struct l_checksum, 1);
	checksum->sk = accept4(fd, NULL, 0, SOCK_CLOEXEC);
	close(fd);

	if (checksum->sk < 0) {
		l_free(checksum);
		return NULL;
	}

	strcpy(checksum->alg_name, "cmac(aes)");
	return checksum;
}

struct l_checksum *l_checksum_new_hmac(enum l_checksum_type type,
					const void *key, size_t key_len)
{
	struct l_checksum *checksum;
	int fd;
	const char *name;

	if (!is_valid_type(type))
		return NULL;

	switch (type) {
	case L_CHECKSUM_MD5:
		name = "hmac(md5)";
		break;
	case L_CHECKSUM_SHA1:
		name = "hmac(sha1)";
		break;
	case L_CHECKSUM_SHA256:
		name = "hmac(sha256)";
		break;
	}

	fd = create_alg(name);
	if (fd < 0)
		return NULL;

	if (setsockopt(fd, SOL_ALG, ALG_SET_KEY, key, key_len) < 0) {
		close(fd);
		return NULL;
	}

	checksum = l_new(struct l_checksum, 1);
	checksum->sk = accept4(fd, NULL, 0, SOCK_CLOEXEC);
	close(fd);

	if (checksum->sk < 0) {
		l_free(checksum);
		return NULL;
	}

	strcpy(checksum->alg_name, name);
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
	static struct {
		const char *name;
		size_t digest_len;
	} digest_lut[] = {
		{ .name = "md5", .digest_len = 16 },
		{ .name = "sha1", .digest_len = 20 },
		{ .name = "sha256", .digest_len = 32 },
		{ .name = "cmac(aes)", .digest_len = 16 },
		{ .name = "hmac(md5)", .digest_len = 16 },
		{ .name = "hmac(sha1)", .digest_len = 20 },
		{ .name = "hmac(sha256)", .digest_len = 32 },
		{ .name = NULL, .digest_len = 0 },
	};
	unsigned char digest[32];
	unsigned int i;

	if (unlikely(!checksum))
		return NULL;

	l_checksum_get_digest(checksum, digest, sizeof(digest));

	for (i = 0; digest_lut[i].name; i++) {
		if (strcmp(digest_lut[i].name, checksum->alg_name))
			continue;

		return l_util_hexstring(digest, digest_lut[i].digest_len);
	}

	return NULL;
}
