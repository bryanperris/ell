/*
 *
 *  Embedded Linux library
 *
 *  Copyright (C) 2016  Intel Corporation. All rights reserved.
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

#include <ell/ell.h>

#define KEY1_STR "This key has exactly _32_ bytes!"
#define KEY1_LEN (strlen(KEY1_STR))
#define KEY2_STR "This key is longer than 32 bytes, just to be different."
#define KEY2_LEN (strlen(KEY2_STR))

static const char *plaintext =
	"The quick brown fox jumps over the lazy dog. "	\
	"Jackdaws love my big sphinx of quartz. "	\
	"Pack my box with five dozen liquor jugs. "	\
	"How razorback-jumping frogs can level six piqued gymnasts!";

static void test_unsupported(const void *data)
{
	struct l_key *key;

	key = l_key_new(42, KEY1_STR, KEY1_LEN);
	assert(!key);
}

static void test_user(const void *data)
{
	struct l_key *key;
	bool ok;
	char buf[64] = { 0 };
	size_t len;
	ssize_t reported_len;

	assert(KEY1_LEN < KEY2_LEN);
	assert(KEY2_LEN < sizeof(buf));

	key = l_key_new(L_KEY_RAW, KEY1_STR, KEY1_LEN);
	assert(key);

	reported_len = l_key_get_payload_size(key);
	assert(reported_len == KEY1_LEN);

	len = KEY1_LEN - 1;
	ok = l_key_extract(key, buf, &len);
	assert(!ok);

	len = sizeof(buf);
	ok = l_key_extract(key, buf, &len);
	assert(ok);
	assert(len == KEY1_LEN);
	assert(!strcmp(buf, KEY1_STR));

	ok = l_key_update(key, KEY2_STR, KEY2_LEN);
	assert(ok);

	len = sizeof(buf);
	ok = l_key_extract(key, buf, &len);
	assert(ok);
	assert(len == KEY2_LEN);
	assert(!strcmp(buf, KEY2_STR));

	l_key_free(key);
}

struct dh_test_vector {
	char *prime;
	char *generator;
	char *priv1;
	char *pub1;
	char *priv2;
	char *pub2;
	char *secret;
};

/* Test cases from http://csrc.nist.gov/groups/STM/cavp/key-management.html#kas
 * http://csrc.nist.gov/groups/STM/cavp/documents/keymgmt/KASTestVectorsFFC2014.zip
 */

/* Parameter set: FB
 * Index: 2
 */
static const struct dh_test_vector dh_valid1 = {
	.prime =
	"ca60d25245efbba8c7f61d2344fd692aa42df7842b83131ad8e6afd94f51adf0"
	"1fc79a5db87ce2f7c2235fec416ae9d1268e1827b179a3602add735d167d6034"
	"cc4f6e33671e6e68bb5340ffc7e8172ed183881d20f773e271ff5db5524bdc3b"
	"8bf3ea9e505c993c7879b2c3575c25e0c66800266998ec45a0f8fcfb44884d07"
	"156ae63b5be321944453a5c425612a6d76d44fda03530423ffe08245a86702f6"
	"b9d7bc87103c4094d9cbb2a69a6560386f025cea444c2779a576efdfbe470209"
	"d091609c29a3321402993f820a67de6044a9a3eae9c11d882de1c19a8dd8f8bd"
	"c4193c432826cac60bed5e691b441a4c6995d1fe3117a9418777e767afdcdeff",
	.generator =
	"758d43fb520121e1ad3d6af76e9e84da1057741594d14ca75d6ca296217df11f"
	"62db8703f3e212c8bbd381a961a83815f41e4135c068d27417d320acce628539"
	"3d8c456bf1298c29545426ede51ae129063159c9467ae7fea75864863a4b2d01"
	"feaf6e3da76caf62cfdb5d63751a6188f31b1191f46c0dd141079b16cf545d7c"
	"8db633759295efeb4357f8c7bb23006b5f541eb8b7d16f8d43d65b69455e1597"
	"27fa281cd80a01c4376922a2f0ddd3e1f61f42297a212f9f27fde0ded87974eb"
	"63eb1bf3f65986bce9868a88590196779f95e00a87bb271ab159e09c2596ae58"
	"e507ab285a0b0b1cf67aac8c31d51bf8da4d0ef99c7e9d5d7cfb765f75cc0a63",
	.priv1 =
	"901729dff82c5cfff88714e327ea3ecc91b196697c4a214fee614222",
	.pub1 =
	"8be42d22a595c7e00c96a17e13976c91fd8da0b9a67ffc5f76295c07df05153d"
	"6c4ee14ce3731f290f3aa06bdd35e2d5e069227a2eea34cb0e7c83d9458a9b90"
	"4f84ef08cab7281ae68a17f18e2a183241b6f4dd7eba7ee2b1b27279ea38c685"
	"70d9747020d111d55963a1680a870bd92637abd24e1050d96584823a7e22ef67"
	"5e54027d20bcd71ecab5d2093e4001f861226b398563a00b88d1dbfcba12315b"
	"9285ed8cbf5d183a6f27c8705b2d2da4563582b9b6c4876f3cdc6e41dd593e04"
	"bac5a3c4598cbe3f67d3bc723de2f13b4847b2266b7f2ae4b7f2f3c092e0fb5c"
	"78b6d65afd54141ec9ba29ec607ccd8c1329bce166029b8395805e6e18441c97",
	.priv2 =
	"7a0fcb52b0497a6830a3efe0828054aa629fc9818bb1562c4a6b1af6",
	.pub2 =
	"3df2f085a43491c109567037d6d21f75fff6e1b458d81f63a29f673c67f1fc64"
	"6fa07a938a678370e2c412e224d8ad8cb5d7d0d1bd2a340d07d107449d7c6498"
	"c3911cb275789fef3e27c3322cad2376b74bce8fd045831f2db8803131a6502b"
	"7a9b6e515e93c1653cc410a2fbea6be0d05b337fe3a992d4c871815adb3218d7"
	"bd10e2bf870006f45658c0e8e3f15e8e7bd67ccd104bf2445b2681a2739effa2"
	"34dc567afeece9c4a1debdbb0c615539eeb756b7d4966ec8354d7add5812abfd"
	"fdd3fb82b284e00c3cbe11c195b85aef818c90f0220575e3eb629a52514b2542"
	"5bd01cb390905874c241d3c9dc771a359694d7bc6bac42b3ababd78005a6360c",
	.secret =
	"8a5b80886761bcfe35c50bd16a5295d88071ad11d8201b0dcac83d1836c0603e"
	"1ced6a7e074e57cd2bc009a74723a88f2dda650110f2b5af8005f5d5b4805ca8"
	"169ee738c188be533c4fac444fc70dd280aad6cb818ecee408f7556dfb0b0af4"
	"f07b26d81dc2037a3fdf57f0d20373b0e63462e20ea5bb9481572dd1b2b5ef26"
	"3dd88148e871e48e8146ceebc49d986dc79f42683ee0d64790f4cac79a857801"
	"69df50d2eb68a6fd76a9c19b20254701d09808c5a072845c467845b492875339"
	"6c1843407acacf2b6d8d9e1f6b07e9e272d553762e4cf8c16da2fb683b74c210"
	"722c4fe576a252353162f9a690de6b76f29db8b8f556942a57499ce310459351",
};

/* Parameter set: FC
 * Count: 22
 */
static const struct dh_test_vector dh_valid2 = {
	.prime =
	"dc53dfa73a49a384f603173c93c17a59baa4c18bf0305e587ded5c8c56f6e44c"
	"645ba8a2eb26c87a9e2be8b28d407eb7a82be004bfbe4ff097ba97b2b4dc980f"
	"349b75540c71120b49c279be3a610414ae984a781382ded04e64cd26dca3cb4e"
	"cf8866db23af4c12db308148f281bbe0953165e0fe58fd6c806ace0152190018"
	"6d0c0b4a3d636bb834bab9218441fb3117814621d5bf4558dfcca4cb8e1e680b"
	"df525760a2cf79352114cd913c64d1b56836be86b2059aca3d4fc18818dab52c"
	"f0031bab41b75f2b27519cc39fd557ba88f6765cd380ace9e7f2ceb9077b6b51"
	"09ce7d4deffb0767717e9a475a5a7ef313daf79dd4026c114df248660de436c7",
	.generator =
	"c05367267fe0dc4fa92250ecceb658054d462be7aeb88334fc6d61a7140278c9"
	"8d2fffee0079cc8906882ef7f9471d7f72aa586a8ed8361c42f88a7a698aa7df"
	"37317ee326af8ade89fbaf17e22b67b674f9801cb5c9858faf469478d255851f"
	"ee2fc2c4a47655f6060c0b23a2a4a343f6031441bbdf934283e11a64326f32c3"
	"6ec1dd64cb92138ae3951488a65df6d1fcdf502fbaf68bbe53cb4bba1eae8a8e"
	"7e7ae98cf71fd50fa58bbc0854f56f2f19c1b2a6ef99cdbce3a92240700c06a2"
	"8c496e9e62f470f4e316ed9b358e8eb9d0c9caefffdab2a7f68b022439ddfaff"
	"9aa389df051fc222be6546212b9480ef19a2e1749ba94f1cdd35e9a1c74c4c42",
	.priv1 =
	"637d28e58d67aef445681844519a9efba5a12331c4d3d73515f1e7426cf57359",
	.pub1 =
	"8d96c1878c86961304081b0c8959ba23cdefa9fb599c6b96ef813e22a7ffaeac"
	"3bac4afdce2625c59e53e8566f86badb56e4ea4c462d58a3de6e0401cc109653"
	"a0c99c7c938af4351f32c995164d0073c701b1cc154a862ba59d0765a9e5af6f"
	"c2f17997fae46afa4afdb1ed654391a30334251e8b5b97b2ba0597177dae047e"
	"c2582bc2755be5036dd06fed1ab74d869ade882da849d94ad9815f6c5b336a43"
	"f26c9f82d8b14699ff961590d6a2b65365e1b1128861eec08c4e840c4f80f19b"
	"ca2d752bf8116a368866fdd8a2c088190654b851957b26e2569f7830b912a447"
	"7ad56d270c295af37ea21310505d344ee624cb9d3a417f999b2efa243dd2435b",
	.priv2 =
	"3ccee743b0c634ae4353e56537a3ec2ce557c5e75f42fcfb3a16f76236112e6f",
	.pub2 =
	"76d7610d90efe2f4c7ac7459261237d36ea709c5ad477f19c334149839d50b83"
	"56ee2b0b089439f31ff153c1a946d3302c3a062523118bc1c495875e6a0459b7"
	"6c7c8e13b2ab0950443fff186f9fd3810309ccb3cee7b102f1e882a5337f6ef7"
	"7124816577d046cb62c6bd6a33ec12d986aec9c16fce316321241e8199bd128a"
	"f460a2e909e724573beb4fd80a653e7348bd3ca1f8f7b697ae5861d4a0fa7d6d"
	"c670449d777627fa88ef4961ebd6ab692a3b023ac181f6e9e215eef80fa7b6b7"
	"44ec03786219f8a46d5f08285cf60c12ad2067691cdfee0c069dd6499844ab8b"
	"306c4f39444c6193214dec93a1529f7914eaf063835f549598c294e196dde86e",
	.secret =
	"a097f9500687fa51fb4005107296b7217b7637407c2df45e01aac5286a0481c3"
	"283ad1613e0ab5143e755e47feacddf9d8f507249bd9ef0d74af69c94c4c808f"
	"f706aca74450668289de5008ed872f700aa2420dfc81593bef8ee922915e3232"
	"3a81a8a7dad8decfa4941f8cb22be95fce9ac1361c5ca5fb58d1b113cd90fb2c"
	"34bc5f3f87b3b5af5baa3af2cff3394a7d35ddbd5254837a438aa59ea86bdac7"
	"dcbc23715030c22263e90150503bb03261a770cb6ff1c9cf1e2cd36de6b85bba"
	"b9ba91c8cd14ecc07dccbdb7c0a8761f347cf3e69326b6370f7833a5b50620bf"
	"d6aab69ab7f1992a9164b93aca29a8348a1ef883a3045f00f9b9ce0e05647502",
};

static const struct dh_test_vector dh_degenerate = {
	.prime =
	"dc53dfa73a49a384f603173c93c17a59baa4c18bf0305e587ded5c8c56f6e44c"
	"645ba8a2eb26c87a9e2be8b28d407eb7a82be004bfbe4ff097ba97b2b4dc980f"
	"349b75540c71120b49c279be3a610414ae984a781382ded04e64cd26dca3cb4e"
	"cf8866db23af4c12db308148f281bbe0953165e0fe58fd6c806ace0152190018"
	"6d0c0b4a3d636bb834bab9218441fb3117814621d5bf4558dfcca4cb8e1e680b"
	"df525760a2cf79352114cd913c64d1b56836be86b2059aca3d4fc18818dab52c"
	"f0031bab41b75f2b27519cc39fd557ba88f6765cd380ace9e7f2ceb9077b6b51"
	"09ce7d4deffb0767717e9a475a5a7ef313daf79dd4026c114df248660de436c7",
	.generator = "01",
	.priv1 = "01",
	.pub1 = "01",
	.priv2 = "01",
	.pub2 = "01",
	.secret = "01",
};

struct testkey {
	struct l_key *key;
	uint8_t *bytes;
	size_t len;
};

static void testkey_from_string(const char *keystr, struct testkey *tk)
{
	tk->bytes = l_util_from_hexstring(keystr, &tk->len);
	assert(tk->bytes);
	assert(tk->len);

	/* Tests assume keys do not have a leading zero byte */
	assert(tk->bytes[0]);

	tk->key = l_key_new(L_KEY_RAW, tk->bytes, tk->len);
	assert(tk->key);
}

static void testkey_free_contents(struct testkey *tk)
{
	l_key_free(tk->key);
	l_free(tk->bytes);
}

static bool equal_with_leading_zeros(uint8_t *buf1, size_t size1,
					uint8_t *buf2, size_t size2)
{
	size_t extrabytes;
	size_t index;

	if (size1 < size2) {
		uint8_t *tmpbuf;
		size_t tmpsize;

		tmpbuf = buf2;
		buf2 = buf1;
		buf1 = tmpbuf;

		tmpsize = size2;
		size2 = size1;
		size1 = tmpsize;
	}

	extrabytes = size1 - size2;

	for (index = 0; index < extrabytes; index++) {
		if (buf1[index])
			return false;
	}

	return !memcmp(buf1 + extrabytes, buf2, size2);
}

static void test_dh(const void *data)
{
	const struct dh_test_vector *vector = data;
	uint8_t *buffer, *secret;
	size_t buflen, secretlen, resultlen;
	struct testkey prime, generator, priv1, pub1, priv2, pub2;

	testkey_from_string(vector->prime, &prime);
	testkey_from_string(vector->generator, &generator);
	testkey_from_string(vector->priv1, &priv1);
	testkey_from_string(vector->pub1, &pub1);
	testkey_from_string(vector->priv2, &priv2);
	testkey_from_string(vector->pub2, &pub2);

	secret = l_util_from_hexstring(vector->secret, &secretlen);
	assert(secret);

	buflen = prime.len;
	buffer = l_malloc(buflen);

	resultlen = buflen;
	memset(buffer, 0, buflen);
	assert(l_key_compute_dh_public(generator.key, priv1.key, prime.key,
					buffer, &resultlen));
	assert(equal_with_leading_zeros(pub1.bytes, pub1.len, buffer,
					resultlen));

	resultlen = buflen;
	memset(buffer, 0, buflen);
	assert(l_key_compute_dh_public(generator.key, priv2.key, prime.key,
					buffer, &resultlen));
	assert(equal_with_leading_zeros(pub2.bytes, pub2.len, buffer,
					resultlen));

	resultlen = buflen - 1;
	memset(buffer, 0, buflen);
	assert(!l_key_compute_dh_public(generator.key, priv2.key, prime.key,
					buffer, &resultlen));

	resultlen = 0;
	memset(buffer, 0, buflen);
	assert(!l_key_compute_dh_public(generator.key, priv2.key, prime.key,
					buffer, &resultlen));

	resultlen = buflen;
	memset(buffer, 0, buflen);
	assert(l_key_compute_dh_secret(pub1.key, priv2.key, prime.key,
					buffer, &resultlen));
	assert(equal_with_leading_zeros(secret, secretlen, buffer, resultlen));

	resultlen = buflen;
	memset(buffer, 0, buflen);
	assert(l_key_compute_dh_secret(pub2.key, priv1.key, prime.key,
					buffer, &resultlen));
	assert(equal_with_leading_zeros(secret, secretlen, buffer, resultlen));

	resultlen = 0;
	memset(buffer, 0, buflen);
	assert(!l_key_compute_dh_secret(pub1.key, priv2.key, prime.key,
					buffer, &resultlen));

	resultlen = secretlen - 1;
	memset(buffer, 0, buflen);
	assert(!l_key_compute_dh_secret(pub1.key, priv2.key, prime.key,
					buffer, &resultlen));

	testkey_free_contents(&prime);
	testkey_free_contents(&generator);
	testkey_free_contents(&priv1);
	testkey_free_contents(&pub1);
	testkey_free_contents(&priv2);
	testkey_free_contents(&pub2);
	l_free(secret);
	l_free(buffer);
}

static void test_simple_keyring(const void *data)
{
	struct l_keyring *ring;
	struct l_key *key1;
	struct l_key *key2;
	bool success;

	ring = l_keyring_new();
	assert(ring);

	key1 = l_key_new(L_KEY_RAW, "1", 1);
	key2 = l_key_new(L_KEY_RAW, "2", 1);

	success = l_keyring_link(ring, key1);
	assert(success);
	success = l_keyring_link(ring, key2);
	assert(success);

	l_key_free(key1);
	success = l_keyring_unlink(ring, key2);
	assert(success);
	l_keyring_free(ring);
	l_key_free(key2);
}

static void test_trusted_keyring(const void *data)
{
	struct l_keyring *ring;
	struct l_keyring *trust;
	uint8_t *cacert;
	size_t cacertlen;
	uint8_t *cert;
	size_t certlen;
	struct l_key *cakey;
	struct l_key *key;
	bool success;

	cacert = l_pem_load_certificate(TESTDATADIR "/cert-ca.pem", &cacertlen);
	assert(cacert);
	cert = l_pem_load_certificate(TESTDATADIR "/cert-server.pem",
					&certlen);
	assert(cert);

	cakey = l_key_new(L_KEY_RSA, cacert, cacertlen);
	assert(cakey);
	key = l_key_new(L_KEY_RSA, cert, certlen);
	assert(key);

	trust = l_keyring_new();
	assert(trust);
	ring = l_keyring_new();
	assert(ring);
	success = l_keyring_restrict(ring, L_KEYRING_RESTRICT_ASYM, trust);
	assert(success);

	success = l_keyring_link(ring, key);
	assert(!success);
	success = l_keyring_link(trust, cakey);
	assert(success);
	success = l_keyring_link(ring, key);
	assert(success);

	l_keyring_free(trust);
	l_keyring_free(ring);
	l_key_free(cakey);
	l_key_free(key);
	l_free(cacert);
	l_free(cert);
}

static void test_trust_chain(const void *data)
{
	struct l_keyring *ring;
	struct l_keyring *trust;
	uint8_t *cacert;
	size_t cacertlen;
	uint8_t *intcert;
	size_t intcertlen;
	uint8_t *cert;
	size_t certlen;
	struct l_key *cakey;
	struct l_key *intkey;
	struct l_key *key;
	bool success;

	cacert = l_pem_load_certificate(TESTDATADIR "/cert-ca.pem", &cacertlen);
	assert(cacert);
	intcert = l_pem_load_certificate(TESTDATADIR "/cert-intca.pem",
						&intcertlen);
	assert(intcert);
	cert = l_pem_load_certificate(TESTDATADIR "/cert-entity-int.pem",
					&certlen);
	assert(cert);

	cakey = l_key_new(L_KEY_RSA, cacert, cacertlen);
	assert(cakey);
	intkey = l_key_new(L_KEY_RSA, intcert, intcertlen);
	assert(intkey);
	key = l_key_new(L_KEY_RSA, cert, certlen);
	assert(key);

	trust = l_keyring_new();
	assert(trust);
	ring = l_keyring_new();
	assert(ring);

	success = l_keyring_restrict(ring, L_KEYRING_RESTRICT_ASYM_CHAIN,
					trust);
	assert(success);
	success = l_keyring_link(ring, key);
	assert(!success);
	success = l_keyring_link(ring, intkey);
	assert(!success);
	success = l_keyring_link(trust, cakey);
	assert(success);
	success = l_keyring_link(ring, key);
	assert(!success);
	success = l_keyring_link(ring, intkey);
	assert(success);
	success = l_keyring_link(ring, key);
	assert(success);

	l_keyring_free(trust);
	l_keyring_free(ring);
	l_key_free(cakey);
	l_key_free(intkey);
	l_key_free(key);
	l_free(cacert);
	l_free(intcert);
	l_free(cert);
}

/* Reference ciphertext:
 * $ openssl rsautl -in reference_plaintext -inkey cert-client.pem -encrypt \
 * > -pkcs -out reference_ciphertext
 * $ xxd -i reference_ciphertext
 *
 * where reference_plaintext is a file containing the 183 characters of
 * plaintext[] (above).
 */
static uint8_t reference_ciphertext[256] = {
	0x45, 0x1a, 0xa1, 0x49, 0x4f, 0x61, 0xf6, 0x96, 0x23, 0x77, 0x0c, 0x33,
	0x56, 0x07, 0xe6, 0x0f, 0xd6, 0x7b, 0x90, 0xd0, 0x4f, 0xc7, 0x9f, 0x34,
	0xd4, 0x99, 0x55, 0x74, 0xd9, 0x68, 0x35, 0x3f, 0xd5, 0xbd, 0x7a, 0xec,
	0xd3, 0xd1, 0x7e, 0xe3, 0xf0, 0xd6, 0x72, 0x7f, 0xb7, 0x20, 0x10, 0x53,
	0x1c, 0xaa, 0x2b, 0xf6, 0x82, 0x66, 0xdf, 0xfe, 0x71, 0x62, 0x4e, 0x97,
	0xdb, 0x83, 0xff, 0xc2, 0xab, 0x79, 0x69, 0xc7, 0xde, 0x77, 0x18, 0x55,
	0x0c, 0xea, 0x01, 0x4e, 0xeb, 0x8b, 0x13, 0xa3, 0xef, 0xc4, 0x29, 0xa6,
	0x51, 0x16, 0x3f, 0xa5, 0xe9, 0x91, 0x91, 0x26, 0x45, 0x98, 0x1f, 0x0b,
	0x34, 0x6e, 0x4a, 0x61, 0xc4, 0xf3, 0x85, 0x78, 0x6b, 0xdf, 0x38, 0x9b,
	0xeb, 0x6d, 0xc2, 0xed, 0xdf, 0xa9, 0xe6, 0xbb, 0x81, 0x84, 0xd9, 0x4a,
	0x42, 0xa6, 0x3b, 0xa9, 0x5b, 0xae, 0xee, 0xaa, 0x6a, 0x3a, 0xc0, 0xcb,
	0x48, 0x5c, 0x61, 0xa0, 0xe2, 0x4c, 0x06, 0x15, 0x7a, 0x8e, 0xe7, 0x47,
	0x9c, 0x03, 0x86, 0x70, 0x00, 0xa1, 0xa8, 0x68, 0x9e, 0x7e, 0xc7, 0x81,
	0x38, 0xb3, 0x00, 0xd4, 0xa9, 0xc2, 0x56, 0xf7, 0xf4, 0x3b, 0x9b, 0xb1,
	0x27, 0xcd, 0xed, 0x2e, 0xf3, 0xa8, 0x9b, 0x08, 0x5e, 0x8a, 0xf3, 0x29,
	0x67, 0xa4, 0x93, 0xc5, 0x68, 0xa5, 0x26, 0x1b, 0x3b, 0x1d, 0xc7, 0x78,
	0x32, 0xd9, 0x81, 0x65, 0x8e, 0x17, 0xb3, 0x17, 0x30, 0x12, 0xe3, 0x78,
	0x23, 0xd9, 0x02, 0x3b, 0xf9, 0x7b, 0x8d, 0x12, 0x4c, 0xff, 0xa0, 0xd2,
	0x0f, 0x59, 0xb9, 0x75, 0xbd, 0x7f, 0xbb, 0x13, 0x8c, 0x6f, 0xbd, 0x00,
	0x67, 0xf3, 0xa0, 0x43, 0x05, 0x5d, 0xb7, 0x64, 0xe3, 0xae, 0x81, 0xe1,
	0x78, 0x5e, 0x81, 0xc5, 0x20, 0xc0, 0xdb, 0xba, 0xd0, 0xbe, 0x1f, 0xc5,
	0x6a, 0xe4, 0x31, 0x46
};

/* Reference signature:
 * $ openssl rsautl -sign -pkcs -in good_plaintext -inkey cert-client-key.pem \
 * -out reference_signature
 * $ xxd -i reference_signature
 *
 * where good_plaintext is a file containing the 183 characters of
 * plaintext[] (above).
 */

uint8_t reference_signature[256] = {
	0xd9, 0x4b, 0x60, 0x5c, 0x20, 0x0d, 0xe1, 0x21, 0x1b, 0x97, 0xcf, 0x7c,
	0xb6, 0x19, 0xf7, 0xbc, 0x5e, 0xf9, 0x0b, 0xaf, 0x71, 0xa3, 0x52, 0x30,
	0xbf, 0xf9, 0xb6, 0x71, 0x20, 0xfb, 0x26, 0x9e, 0xb2, 0x1c, 0x98, 0x79,
	0x8e, 0xee, 0xd7, 0xbf, 0x9b, 0x4b, 0xd2, 0xd0, 0xc7, 0xd1, 0xb2, 0x9e,
	0xf2, 0x7c, 0xa9, 0xb2, 0x1d, 0x57, 0x96, 0xcc, 0xb2, 0x12, 0x47, 0x3b,
	0xaf, 0xca, 0xa4, 0x96, 0xdd, 0xbf, 0x58, 0xd0, 0x9e, 0xdf, 0x27, 0x73,
	0x53, 0x78, 0xc5, 0xa0, 0x9e, 0x73, 0xd7, 0x7b, 0x78, 0x1b, 0xbe, 0x17,
	0x5b, 0x34, 0x1d, 0x05, 0x26, 0xbd, 0x15, 0x82, 0x7f, 0x4a, 0xe1, 0xe1,
	0xc4, 0x19, 0xeb, 0x08, 0xdb, 0xca, 0x2b, 0x66, 0x6a, 0x6d, 0xd6, 0x77,
	0x06, 0x55, 0xb0, 0x6d, 0xe2, 0x44, 0xdf, 0x9f, 0x6f, 0xd6, 0x15, 0xe0,
	0xe5, 0xa9, 0xd1, 0x8a, 0xc4, 0xdd, 0x03, 0xb3, 0xfa, 0x61, 0xeb, 0xed,
	0xc8, 0xb8, 0x65, 0x32, 0x72, 0x38, 0x4b, 0xc8, 0x52, 0x79, 0xd4, 0x4b,
	0x48, 0xc9, 0xc5, 0x90, 0x14, 0x27, 0xef, 0x87, 0x6b, 0x07, 0x48, 0xa9,
	0x26, 0x44, 0x5b, 0xd9, 0x93, 0xd8, 0x00, 0x55, 0xc0, 0xa3, 0x0d, 0xf7,
	0x42, 0x12, 0x7b, 0x3c, 0x79, 0xc2, 0x3c, 0x2b, 0xf4, 0x66, 0xb0, 0x84,
	0xb0, 0x2f, 0x69, 0xd5, 0x32, 0xad, 0x78, 0xee, 0xcc, 0xc7, 0xdf, 0x0b,
	0xdd, 0x31, 0xa8, 0xc0, 0x93, 0x34, 0xe6, 0x47, 0xa9, 0x0f, 0x71, 0x2d,
	0x0e, 0x58, 0x51, 0x64, 0x40, 0x5b, 0x02, 0x4c, 0x15, 0xc9, 0x93, 0x3b,
	0x2f, 0x3f, 0x28, 0x2c, 0xaf, 0x70, 0x20, 0x9e, 0xc3, 0x50, 0xca, 0x28,
	0x6a, 0xce, 0x29, 0x39, 0x50, 0x99, 0xda, 0x97, 0xc3, 0x9e, 0x00, 0x3f,
	0xbb, 0x60, 0x4d, 0xf0, 0x6a, 0x5c, 0xc8, 0x81, 0x95, 0x32, 0x5f, 0x02,
	0xfe, 0x1a, 0x1a, 0x6e
};

static void test_key_crypto(const void *data)
{
	uint8_t *cert;
	size_t certlen;
	uint8_t *pubcert;
	size_t pubcertlen;
	struct l_key *key;
	struct l_key *pubkey;
	bool is_public;
	size_t keybits;
	bool success;
	uint8_t ciphertext[256];
	uint8_t decrypted[256];
	ssize_t len;
	int hash = L_CHECKSUM_NONE;
	int rsa = L_KEY_RSA_PKCS1_V1_5;

	cert = l_pem_load_private_key(TESTDATADIR "/cert-client-key-pkcs8.pem",
					NULL, &certlen);
	assert(cert);
	pubcert = l_pem_load_certificate(TESTDATADIR "/cert-client.pem",
						&pubcertlen);
	assert(pubcert);

	key = l_key_new(L_KEY_RSA, cert, certlen);
	assert(key);
	pubkey = l_key_new(L_KEY_RSA, pubcert, pubcertlen);
	assert(pubkey);

	success = l_key_get_info(key, rsa, hash, &keybits, &is_public);
	assert(success);
	assert(keybits == 2048);
	assert(!is_public);

	success = l_key_get_info(key, rsa, L_CHECKSUM_NONE, &keybits,
					&is_public);
	assert(success);
	assert(keybits == 2048);
	assert(!is_public);

	success = l_key_get_info(pubkey, rsa, hash, &keybits, &is_public);
	assert(success);
	assert(keybits == 2048);
	assert(is_public);

	memset(ciphertext, 0, sizeof(ciphertext));
	memset(decrypted, 0, sizeof(decrypted));

	len = l_key_encrypt(pubkey, rsa, hash, plaintext, ciphertext,
				strlen(plaintext), sizeof(ciphertext));
	assert(len == sizeof(ciphertext));

	/* Can't decrypt with public key */
	len = l_key_decrypt(pubkey, rsa, hash, ciphertext, decrypted,
				sizeof(ciphertext), sizeof(decrypted));
	assert(len < 0);

	len = l_key_decrypt(key, rsa, hash, ciphertext, decrypted,
				sizeof(ciphertext), sizeof(decrypted));
	assert(len == (ssize_t)strlen(plaintext));
	assert(strcmp(plaintext, (char *)decrypted) == 0);

	/* Decrypt reference ciphertext */
	memset(decrypted, 0, sizeof(decrypted));
	len = l_key_decrypt(key, rsa, hash, reference_ciphertext, decrypted,
				sizeof(reference_ciphertext),
				sizeof(decrypted));
	assert(len == (ssize_t)strlen(plaintext));
	assert(strcmp(plaintext, (char *)decrypted) == 0);

	/* Decrypt corrupted ciphertext */
	memset(decrypted, 0, sizeof(decrypted));
	reference_ciphertext[0] = reference_ciphertext[0] ^ (uint8_t)0xFF;
	len = l_key_decrypt(key, rsa, hash, reference_ciphertext, decrypted,
				sizeof(reference_ciphertext),
				sizeof(decrypted));
	assert(len < 0);

	/* Can't sign with public key */
	len = l_key_sign(pubkey, rsa, hash, plaintext, ciphertext,
				strlen(plaintext), sizeof(ciphertext));
	assert(len < 0);

	len = l_key_sign(key, rsa, hash, plaintext, ciphertext,
				strlen(plaintext), sizeof(ciphertext));
	assert(len == sizeof(ciphertext));

	success = l_key_verify(pubkey, rsa, hash, plaintext, ciphertext,
				strlen(plaintext), sizeof(ciphertext));
	assert(success);

	success = l_key_verify(key, rsa, hash, plaintext, ciphertext,
				strlen(plaintext), sizeof(ciphertext));
	assert(success);

	success = l_key_verify(pubkey, rsa, hash, plaintext,
				reference_signature, strlen(plaintext),
				sizeof(reference_signature));
	assert(success);

	/* Corrupt signature */
	ciphertext[42] = ciphertext[52] ^ (uint8_t)0xFF;
	success = l_key_verify(key, rsa, hash, plaintext, ciphertext,
				strlen(plaintext), sizeof(ciphertext));
	assert(!success);

	l_key_free(key);
	l_key_free(pubkey);
	l_free(cert);
	l_free(pubcert);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("unsupported", test_unsupported, NULL);

	l_test_add("user key", test_user, NULL);

	l_test_add("Diffie-Hellman 1", test_dh, &dh_valid1);
	l_test_add("Diffie-Hellman 2", test_dh, &dh_valid2);
	l_test_add("Diffie-Hellman 3", test_dh, &dh_degenerate);

	l_test_add("simple keyring", test_simple_keyring, NULL);
	l_test_add("trusted keyring", test_trusted_keyring, NULL);
	l_test_add("trust chain", test_trust_chain, NULL);

	l_test_add("key crypto", test_key_crypto, NULL);

	return l_test_run();
}
