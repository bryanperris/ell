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
#include <errno.h>
#include <sys/socket.h>

#include "util.h"
#include "cipher.h"
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

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define is_valid_type(type)  ((type) <= L_CIPHER_DES3_EDE_CBC)

struct l_cipher {
	enum l_cipher_type type;
	int encrypt_sk;
	int decrypt_sk;
};

static int create_alg(enum l_cipher_type type,
				const void *key, size_t key_length)
{
	struct sockaddr_alg salg;
	int sk;
	int ret;

	sk = socket(PF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sk < 0)
		return -errno;

	memset(&salg, 0, sizeof(salg));
	salg.salg_family = AF_ALG;
	strcpy((char *) salg.salg_type, "skcipher");

	switch (type) {
	case L_CIPHER_AES:
		strcpy((char *) salg.salg_name, "ecb(aes)");
		break;
	case L_CIPHER_AES_CBC:
		strcpy((char *) salg.salg_name, "cbc(aes)");
		break;
	case L_CIPHER_ARC4:
		strcpy((char *) salg.salg_name, "ecb(arc4)");
		break;
	case L_CIPHER_DES3_EDE_CBC:
		strcpy((char *) salg.salg_name, "cbc(des3_ede)");
		break;
	}

	if (bind(sk, (struct sockaddr *) &salg, sizeof(salg)) < 0) {
		close(sk);
		return -1;
	}

	if (setsockopt(sk, SOL_ALG, ALG_SET_KEY, key, key_length) < 0) {
		close(sk);
		return -1;
	}

	ret = accept4(sk, NULL, 0, SOCK_CLOEXEC);
	close(sk);

	return ret;
}

LIB_EXPORT struct l_cipher *l_cipher_new(enum l_cipher_type type,
						const void *key,
						size_t key_length)
{
	struct l_cipher *cipher;

	if (unlikely(!key))
		return NULL;

	if (!is_valid_type(type))
		return NULL;

	cipher = l_new(struct l_cipher, 1);
	cipher->type = type;

	cipher->encrypt_sk = create_alg(type, key, key_length);
	if (cipher->encrypt_sk < 0)
		goto error_free;

	cipher->decrypt_sk = create_alg(type, key, key_length);
	if (cipher->decrypt_sk < 0)
		goto error_close;

	return cipher;

error_close:
	close(cipher->encrypt_sk);
error_free:
	l_free(cipher);
	return NULL;
}

LIB_EXPORT void l_cipher_free(struct l_cipher *cipher)
{
	if (unlikely(!cipher))
		return;

	close(cipher->encrypt_sk);
	close(cipher->decrypt_sk);

	l_free(cipher);
}

static bool operate_cipher(int sk, __u32 operation,
				const void *in, void *out, size_t len)
{
	char c_msg_buf[CMSG_SPACE(sizeof(operation))] = {};
	struct msghdr msg = {};
	struct cmsghdr *c_msg;
	struct iovec iov;

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

	if (sendmsg(sk, &msg, 0) < 0)
		return false;

	if (read(sk, out, len) < 0)
		return false;

	return true;
}

LIB_EXPORT bool l_cipher_encrypt(struct l_cipher *cipher,
					const void *in, void *out, size_t len)
{
	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	return operate_cipher(cipher->encrypt_sk, ALG_OP_ENCRYPT, in, out, len);
}

LIB_EXPORT bool l_cipher_decrypt(struct l_cipher *cipher,
					const void *in, void *out, size_t len)
{
	if (unlikely(!cipher))
		return false;

	if (unlikely(!in) || unlikely(!out))
		return false;

	return operate_cipher(cipher->decrypt_sk, ALG_OP_DECRYPT, in, out, len);
}
