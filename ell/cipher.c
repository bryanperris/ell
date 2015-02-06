/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2015  Intel Corporation. All rights reserved.
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
#include "cipher.h"
#include "private.h"

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

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

struct af_alg_iv {
	__u32   ivlen;
	__u8    iv[0];
};

/* Socket options */
#define ALG_SET_KEY	1
#define ALG_SET_IV	2
#define ALG_SET_OP	3

/* Operations */
#define ALG_OP_DECRYPT	0
#define ALG_OP_ENCRYPT	1

#else
#include <linux/if_alg.h>
#endif

#define is_valid_type(type)  ((type) <= L_CIPHER_ARC4)

struct l_cipher {
	enum l_cipher_type type;
	int b_sk;
	int sk;
	void *key;
	size_t key_length;
	bool enc;
	bool dec;
};

LIB_EXPORT struct l_cipher *l_cipher_new(enum l_cipher_type type,
						const void *key,
						size_t key_length)
{
	struct sockaddr_alg salg;
	struct l_cipher *cipher;

	if (unlikely(!key))
		return NULL;

	if (!is_valid_type(type))
		return NULL;

	cipher = l_new(struct l_cipher, 1);

	cipher->type = type;

	cipher->b_sk = socket(PF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (cipher->b_sk < 0)
		goto error;

	memset(&salg, 0, sizeof(salg));
	salg.salg_family = AF_ALG;
	strcpy((char *) salg.salg_type, "skcipher");

	switch (type) {
	case L_CIPHER_AES:
		strcpy((char *) salg.salg_name, "ecb(aes)");
		break;
	case L_CIPHER_ARC4:
		strcpy((char *) salg.salg_name, "ecb(arc4)");
		break;
	}

	if (bind(cipher->b_sk, (struct sockaddr *) &salg, sizeof(salg)) < 0)
		goto error;

	cipher->key = l_memdup(key, key_length);
	cipher->key_length = key_length;

	cipher->sk = accept4(cipher->b_sk, NULL, 0, SOCK_CLOEXEC);
	if (cipher->sk < 0)
		goto error;

	return cipher;
error:
	if (cipher->b_sk > 0)
		close(cipher->b_sk);

	if (cipher->key)
		l_free(cipher->key);

	l_free(cipher);

	return NULL;
}

LIB_EXPORT void l_cipher_free(struct l_cipher *cipher)
{
	if (unlikely(!cipher))
		return;

	close(cipher->sk);
	close(cipher->b_sk);

	if (cipher->key)
		l_free(cipher->key);

	l_free(cipher);
}

static void operate_cipher(struct l_cipher *cipher, __u32 operation,
				const void *in, void *out, size_t len)
{
	char c_msg_buf[CMSG_SPACE(sizeof(operation))] = {};
	struct msghdr msg = {};
	bool setkey = false;
	struct cmsghdr *c_msg;
	struct iovec iov;

	if (operation == ALG_OP_ENCRYPT && !cipher->enc) {
		setkey = cipher->enc = true;
		cipher->dec = false;
	} else if (operation == ALG_OP_DECRYPT && !cipher->dec) {
		setkey = cipher->dec = true;
		cipher->enc = false;
	}

	if (setkey) {
		if (setsockopt(cipher->b_sk, SOL_ALG, ALG_SET_KEY,
					cipher->key, cipher->key_length) < 0)
			return;
	}

	msg.msg_control = c_msg_buf;
	msg.msg_controllen = sizeof(c_msg_buf);

	c_msg = CMSG_FIRSTHDR(&msg);
	c_msg->cmsg_level = SOL_ALG;
	c_msg->cmsg_type = ALG_SET_OP;
	c_msg->cmsg_len = CMSG_LEN(sizeof(operation));
	memcpy(CMSG_DATA(c_msg), &operation, sizeof(operation));

	iov.iov_base = (void *) in;
	iov.iov_len = len;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	if (sendmsg(cipher->sk, &msg, 0) < 0)
		return;

	if (read(cipher->sk, out, len) < 0)
		return;
}

LIB_EXPORT void l_cipher_encrypt(struct l_cipher *cipher,
					const void *in, void *out, size_t len)
{
	if (unlikely(!cipher))
		return;

	if (unlikely(!in) || unlikely(!out))
		return;

	operate_cipher(cipher, ALG_OP_ENCRYPT, in, out, len);
}

LIB_EXPORT void l_cipher_decrypt(struct l_cipher *cipher,
					const void *in, void *out, size_t len)
{
	if (unlikely(!cipher))
		return;

	if (unlikely(!in) || unlikely(!out))
		return;

	operate_cipher(cipher, ALG_OP_DECRYPT, in, out, len);
}
