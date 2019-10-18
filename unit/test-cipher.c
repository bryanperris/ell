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

#include <assert.h>
#include <alloca.h>
#include <stdio.h>

#include <ell/ell.h>

#define FIXED_STR  "The quick brown fox jumps over the lazy dog. " \
		   "Jackdaws love my big sphinx of quartz. "       \
		   "Pack my box with five dozen liquor jugs. "     \
		   "How razorback-jumping frogs can level six piqued gymnasts!"
#define FIXED_LEN  (strlen(FIXED_STR))

#define KEY_STR "This key has exactly _32_ bytes!"
#define KEY_LEN (strlen(KEY_STR))

static void test_unsupported(const void *data)
{
	struct l_cipher *cipher;

	cipher = l_cipher_new(42, KEY_STR, KEY_LEN);
	assert(!cipher);
}

static void test_aes(const void *data)
{
	struct l_cipher *cipher;
	char buf[256];
	int r;

	cipher = l_cipher_new(L_CIPHER_AES, KEY_STR, KEY_LEN);
	assert(cipher);

	memcpy(buf, FIXED_STR, FIXED_LEN);

	l_cipher_encrypt(cipher, buf, buf, FIXED_LEN);

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(r);

	l_cipher_decrypt(cipher, buf, buf, FIXED_LEN);

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(!r);

	l_cipher_free(cipher);
}

static void test_aes_ctr(const void *data)
{
	struct l_cipher *cipher;
	uint8_t iv[8] = { 0 };
	char buf[256];
	int r;

	cipher = l_cipher_new(L_CIPHER_AES_CTR, KEY_STR, KEY_LEN);
	assert(cipher);

	l_cipher_set_iv(cipher, iv, sizeof(iv));

	memcpy(buf, FIXED_STR, FIXED_LEN);

	l_cipher_encrypt(cipher, buf, buf, FIXED_LEN);

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(r);

	l_cipher_decrypt(cipher, buf, buf, FIXED_LEN);

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(!r);

	l_cipher_free(cipher);
}

static void test_arc4(const void *data)
{
	struct l_cipher *cipher;
	char buf[256];
	int r;

	static const unsigned char expect_plaintext[] = {
		0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3,
	};
	static const unsigned char expect_pedia[] = {
		0x10, 0x21, 0xbf, 0x04, 0x20,
	};
	static const unsigned char expect_attack[] = {
		0x45, 0xa0, 0x1f, 0x64, 0x5f, 0xc3, 0x5b, 0x38, 0x35, 0x52,
		0x54, 0x4b, 0x9b, 0xf5,
	};

	cipher = l_cipher_new(L_CIPHER_ARC4, "Key", 3);
	assert(cipher);
	l_cipher_encrypt(cipher, "Plaintext", buf, 9);
	assert(!memcmp(buf, expect_plaintext, 9));
	l_cipher_free(cipher);

	cipher = l_cipher_new(L_CIPHER_ARC4, "Wiki", 4);
	assert(cipher);
	l_cipher_encrypt(cipher, "pedia", buf, 5);
	assert(!memcmp(buf, expect_pedia, 5));
	l_cipher_free(cipher);

	cipher = l_cipher_new(L_CIPHER_ARC4, "Secret", 6);
	assert(cipher);
	l_cipher_encrypt(cipher, "Attack at dawn", buf, 14);
	assert(!memcmp(buf, expect_attack, 14));
	l_cipher_free(cipher);

	cipher = l_cipher_new(L_CIPHER_ARC4, KEY_STR, KEY_LEN);
	assert(cipher);

	memcpy(buf, FIXED_STR, FIXED_LEN);

	l_cipher_encrypt(cipher, buf, buf, FIXED_LEN);

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(r);

	l_cipher_decrypt(cipher, buf, buf, FIXED_LEN);

	r = memcmp(buf, FIXED_STR, FIXED_LEN);
	assert(!r);

	l_cipher_free(cipher);
}

struct aead_test_vector {
	enum l_aead_cipher_type type;
	char *aad;
	char *plaintext;
	char *key;
	char *nonce;
	char *ciphertext;
	char *tag;
};

static const struct aead_test_vector ccm_long_nonce = {
	.type = L_AEAD_CIPHER_AES_CCM,
	.aad =
	"333b6b8fda49c6e671bad05c7e2cafa88bd47f9b0aef1a358bc87d04f26f6c82",
	.plaintext =
	"1293201eb30ddd693b2eb23c1e6c20d5add2202afc71679ca2eba14f73b77bcd",
	.key = "fa536cf6c309d45c1baaa658f674758d",
	.nonce = "e0c5241bf0014ca88511d73a30",
	.ciphertext =
	"2e54ebaa38da9a2b03a1147495565c31d07e793b01fd28b2adeacac6f76ae84e",
	.tag = "e0a03b982c5afc8a937373d7d2b0e7a3"
};

static const struct aead_test_vector ccm_short_nonce = {
	.type = L_AEAD_CIPHER_AES_CCM,
	.plaintext =
	"a3b3fdf26d213f83c5f656b00f77253b68959c188767d584914887602c787595",
	.aad =
	"fcc20524894b4603fefb8029eff485a513ce4753d0d3a27c3a2c69088fa7fab7",
	.key = "7d84efac51291e868c7b7702181a3936",
	.nonce = "1bb3e62620462a",
	.ciphertext =
	"3222192ee773cef4a87175b73b3875320f18b7e016d17d52fb01f0f6ca10bb5f",
	.tag = "ee007aafe91135c39855ebf3db96d7ff"
};

static const struct aead_test_vector ccm_no_aad = {
	.type = L_AEAD_CIPHER_AES_CCM,
	.plaintext =
	"90795fffab99cffdeee5cadafe448ea4df74c480f9d7e1e481ee49adeee2732a",
	.key = "7b3da7d5ef41b5eef19cf8fb4ca19519",
	.nonce = "96722de7516afb",
	.ciphertext =
	"9160dd0e0a8ddd13bf4acb0c6f3cf4794c5459d36a378cfb4a31e6b00840d78a",
	.tag = "efd1dc938802cd845a16f32a60eabd0f"
};

/* https://tools.ietf.org/html/draft-mcgrew-gcm-test-01 */

static const struct aead_test_vector gcm_test1 = {
	.type = L_AEAD_CIPHER_AES_GCM,
	.aad = "000043218765432100000000",
	.plaintext =
	"45000048699a000080114db7c0a80102c0a801010a9bf15638d3010000010000"
	"00000000045f736970045f756470037369700963796265726369747902646b00"
	"0021000101020201",
	/* 128-bit key */
	.key = "4c80cdefbb5d10da906ac73c3613a634",
	.nonce = "2e443b684956ed7e3b244cfe",
	.ciphertext =
	"fecf537e729d5b07dc30df528dd22b768d1b98736696a6fd348509fa13ceac34"
	"cfa2436f14a3f3cf65925bf1f4a13c5d15b21e1884f5ff6247aeabb786b93bce"
	"61bc17d768fd9732",
	.tag = "459018148f6cbe722fd04796562dfdb4",
};

static const struct aead_test_vector gcm_test2 = {
	.type = L_AEAD_CIPHER_AES_GCM,
	.aad = "0000a5f80000000a",
	.plaintext =
	"45000028a4ad4000400678800a01038f0a010612802306b8cb712602dd6bb03e"
	"501016d075680001",
	/* 192-bit key */
	.key = "feffe9928665731c6d6a8f9467308308feffe9928665731c",
	.nonce = "cafebabefacedbaddecaf888",
	.ciphertext =
	"a5b1f8066029aea40e598b8122de02420938b3ab33f828e687b8858b5bfbdbd0"
	"315b27452144cc77",
	.tag = "95457b9652037f5318027b5b4cd7a636",
};

static const struct aead_test_vector gcm_test3 = {
	.type = L_AEAD_CIPHER_AES_GCM,
	.aad = "4a2cbfe300000002",
	.plaintext =
	"4500003069a6400080062690c0a801029389155e0a9e008b2dc57ee000000000"
	"7002400020bf0000020405b40101040201020201",
	/* 256-bit key */
	.key =
	"abbccddef00112233445566778899aababbccddef00112233445566778899aab",
	.nonce = "112233440102030405060708",
	.ciphertext =
	"ff425c9b724599df7a3bcd510194e00d6a78107f1b0b1cbf06efae9d65a5d763"
	"748a637985771d347f0545659f14e99def842d8e",
	.tag = "b335f4eecfdbf831824b4c4915956c96",
};

static const struct aead_test_vector gcm_test4 = {
	.type = L_AEAD_CIPHER_AES_GCM,
	.aad = "0000000000000001",
	.plaintext =
	"4500003c99c500008001cb7a40679318010101010800075c0200440061626364"
	"65666768696a6b6c6d6e6f707172737475767761626364656667686901020201",
	.key = "00000000000000000000000000000000",
	.nonce = "000000000000000000000000",
	.ciphertext =
	"4688daf2f973a392732909c331d56d60f694abaa414b5e7ff5fdcdfff5e9a284"
	"456476492719ffb64de7d9dca1e1d894bc3bd57873ed4d181d19d4d5c8c18af3",
	.tag = "f821d496eeb096e98ad2b69e4799c71d",
};

static const struct aead_test_vector gcm_test5 = {
	.type = L_AEAD_CIPHER_AES_GCM,
	.aad = "335467aeffffffff",
	.plaintext = "01020201",
	.key = "7d773d00c144c525ac619d18c84a3f47",
	.nonce = "d966426743457e9182443bc6",
	.ciphertext = "437f866b",
	.tag = "cb3f699fe9b0822bac961c4504bef270",
};

static const struct aead_test_vector gcm_test6 = {
	.type = L_AEAD_CIPHER_AES_GCM,
	.aad =
	"0000432100000007000000000000000045000030da3a00008001df3bc0a80005"
	"c0a800010800c6cd020007006162636465666768696a6b6c6d6e6f7071727374"
	"01020201",
	.key = "4c80cdefbb5d10da906ac73c3613a634",
	.nonce = "22433c640000000000000000",
	.tag = "f2a9a836e155106aa8dcd618e4099aaa",
};

static void test_aead(const void *data)
{
	static uint8_t empty[] = { };
	struct l_aead_cipher *cipher;
	char *encbuf;
	size_t encbuflen;
	char *decbuf;
	size_t decbuflen;
	int r;
	bool success;
	const struct aead_test_vector *tv = data;

	size_t ptlen = 0;
	uint8_t *pt = empty;
	size_t aadlen = 0;
	uint8_t *aad = NULL;
	size_t keylen;
	uint8_t *key = l_util_from_hexstring(tv->key, &keylen);
	size_t noncelen;
	uint8_t *nonce = l_util_from_hexstring(tv->nonce, &noncelen);
	size_t ctlen = 0;
	uint8_t *ct = empty;
	size_t taglen;
	uint8_t *tag = l_util_from_hexstring(tv->tag, &taglen);

	if (tv->plaintext) {
		pt = l_util_from_hexstring(tv->plaintext, &ptlen);
		assert(pt);
	}

	if (tv->ciphertext) {
		ct = l_util_from_hexstring(tv->ciphertext, &ctlen);
		assert(ct);
	}

	if (tv->aad) {
		aad = l_util_from_hexstring(tv->aad, &aadlen);
		assert(aad);
	}

	assert(key);
	assert(nonce);
	assert(tag);

	decbuflen = ptlen;
	decbuf = alloca(decbuflen);
	memset(decbuf, 0, decbuflen);

	encbuflen = ctlen + taglen;
	encbuf = alloca(encbuflen);
	memset(encbuf, 0, encbuflen);

	cipher = l_aead_cipher_new(tv->type, key, keylen, taglen);
	assert(cipher);

	success = l_aead_cipher_encrypt(cipher, pt, ptlen, aad, aadlen,
					nonce, noncelen, encbuf, encbuflen);
	if (!success) {
		printf("* Some kernel versions before v4.9 have a known AEAD\n"
			"* bug. If the system running this test is using a\n"
			"* v4.8 or earlier kernel, a failure here is likely\n"
			"* due to that kernel bug.\n");
	}
	assert(success);

	assert(memcmp(encbuf, ct, ctlen) == 0);
	assert(memcmp(encbuf + ctlen, tag, taglen) == 0);

	success = l_aead_cipher_decrypt(cipher, encbuf, encbuflen, aad, aadlen,
					nonce, noncelen, decbuf, decbuflen);
	assert (success);

	r = memcmp(decbuf, pt, ptlen);
	assert(!r);

	l_aead_cipher_free(cipher);

	if (tv->plaintext)
		l_free(pt);

	l_free(key);
	l_free(aad);
	l_free(nonce);

	if (tv->ciphertext)
		l_free(ct);

	l_free(tag);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("unsupported", test_unsupported, NULL);

	if (l_cipher_is_supported(L_CIPHER_AES))
		l_test_add("aes", test_aes, NULL);

	if (l_cipher_is_supported(L_CIPHER_AES_CTR))
		l_test_add("aes_ctr", test_aes_ctr, NULL);

	if (l_cipher_is_supported(L_CIPHER_ARC4))
		l_test_add("arc4", test_arc4, NULL);

	if (l_aead_cipher_is_supported(L_AEAD_CIPHER_AES_CCM)) {
		l_test_add("aes_ccm long nonce", test_aead, &ccm_long_nonce);
		l_test_add("aes_ccm short nonce", test_aead, &ccm_short_nonce);
		l_test_add("aes_ccm no AAD", test_aead, &ccm_no_aad);
	}

	if (l_aead_cipher_is_supported(L_AEAD_CIPHER_AES_GCM)) {
		l_test_add("aes_gcm test 1", test_aead, &gcm_test1);
		l_test_add("aes_gcm test 2", test_aead, &gcm_test2);
		l_test_add("aes_gcm test 3", test_aead, &gcm_test3);
		l_test_add("aes_gcm test 4", test_aead, &gcm_test4);
		l_test_add("aes_gcm test 5", test_aead, &gcm_test5);
		l_test_add("aes_gcm test 6", test_aead, &gcm_test6);
	}

	return l_test_run();
}
